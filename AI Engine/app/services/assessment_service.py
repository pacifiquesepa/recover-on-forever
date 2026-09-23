from __future__ import annotations

import json
import re
import random
from pathlib import Path
from typing import Any, Dict, List

from app.models import AssessmentGenerationResult, QuestionModel


class AssessmentService:
    """Generates structured assessment questions from curriculum context."""

    def __init__(self):
        dataset_path = Path(__file__).resolve().parents[2] / "data" / "curriculum_dataset.json"
        advanced_path = Path(__file__).resolve().parents[2] / "data" / "advanced_question_bank.json"
        trained_path = Path(__file__).resolve().parents[2] / "data" / "trained_question_bank.json"
        curriculum_map_path = Path(__file__).resolve().parents[2] / "data" / "dataset" / "curriculum_map.json"
        self.curriculum = json.loads(dataset_path.read_text(encoding="utf-8"))
        self.advanced = json.loads(advanced_path.read_text(encoding="utf-8")) if advanced_path.exists() else {}
        self.curriculum_map = json.loads(curriculum_map_path.read_text(encoding="utf-8")) if curriculum_map_path.exists() else {}
        self.trained_path = trained_path
        self.trained = json.loads(trained_path.read_text(encoding="utf-8")) if trained_path.exists() else []
        self.training_source_path = Path(__file__).resolve().parents[2] / "data" / "dataset" / "question_generation.jsonl"
        self._enrich_trained_scope()
        self.type_templates = {
            "multiple_choice": self._generate_multiple_choice,
            "match": self._generate_match,
            "fill_in_gap": self._generate_fill_in_gap,
            "rearrange": self._generate_rearrange,
            "drag_and_drop": self._generate_drag_and_drop,
            "open_question": self._generate_open_question,
        }

    def curriculum_topics(self, class_name: str | None, subject: str | None, unit: str | None = None) -> List[str]:
        if not class_name or not subject:
            return []
        normalized_class = self.normalize_class_name(class_name)
        class_map = self.curriculum_map.get("primary", {}).get(normalized_class, {})
        subject_map = class_map.get(subject, {})
        if unit and unit in subject_map and isinstance(subject_map[unit], dict):
            return list(subject_map[unit].get("topics", []))
        if isinstance(subject_map, dict):
            topics = subject_map.get("topics")
            if isinstance(topics, list):
                return topics
        return []

    def generate_assessment(self, request: Dict[str, Any]) -> AssessmentGenerationResult:
        subject = request.get("subject_name") or "General Subject"
        unit = request.get("unit") or ""
        class_name = self.normalize_class_name(request.get("class_name")) or request.get("class_name")
        topic = request.get("topic") or f"{unit or 'selected unit'} activities"
        book_context = request.get("book_context") or []
        book_sources = self._evaluate_book(book_context, subject, unit, class_name)
        question_types = request.get("question_types", [])
        counts = request.get("counts", {})
        difficulty = request.get("difficulty", "medium")
        if difficulty not in {"easy", "medium", "strong"}:
            difficulty = "medium"
        questions: List[QuestionModel] = []
        seen_prompts = set()
        for question_type in question_types:
            generator = self.type_templates.get(question_type)
            if not generator:
                continue
            for index in range(int(counts.get(question_type, 0))):
                dataset_bank = self._bank_for(subject, unit, topic, difficulty, question_type)
                source_bank = book_sources if question_type == "open_question" and book_sources else dataset_bank
                question = generator(subject, topic, unit, class_name, index, difficulty, source_bank)
                if question_type == "multiple_choice":
                    self._vary_options(question, index)
                if question.prompt.lower() in seen_prompts:
                    question.prompt = f"{question.prompt} Use a different example from {unit or topic} (variant {index + 1})."
                seen_prompts.add(question.prompt.lower())
                question.id = f"{question_type}-{len(questions) + 1}"
                question.metadata = {**question.metadata, "subject": subject, "unit": unit, "topic": topic, "source": "uploaded_book" if book_sources else question.metadata.get("source", "curriculum_dataset"), "book_evaluated": bool(book_sources)}
                if str(request.get("output_language", "English")).lower() == "kinyarwanda":
                    question.metadata = self._localize_metadata(question.metadata)
                questions.append(question)

        total_points = sum(question.points for question in questions)
        return AssessmentGenerationResult(
            subject=subject,
            unit=unit,
            topic=topic,
            class_name=class_name,
            difficulty=difficulty,
            book_evaluated=bool(book_sources),
            total_questions=len(questions),
            total_points=total_points,
            questions=questions,
        )

    @staticmethod
    def _evaluate_book(documents: List[Dict[str, Any]], subject: str, unit: str, class_name: str | None) -> List[Dict[str, Any]]:
        """Turn matched textbook pages into safe, reviewable question sources."""
        sources = []
        unit_terms = {term for term in re.findall(r"[a-z0-9]+", unit.lower()) if term != "unit"}
        for document in documents:
            text = str(document.get("text", ""))
            lower_text = text.lower()
            if unit_terms and not any(term in lower_text for term in unit_terms):
                continue
            lines = [re.sub(r"\s+", " ", line).strip(" -") for line in text.splitlines()]
            candidates = [line for line in lines if len(line) >= 18 and ("activity" in line.lower() or "question" in line.lower() or "exercise" in line.lower() or "?" in line or re.match(r"^\d+[.)]", line))]
            for line in candidates[:20]:
                sources.append({
                    "prompt": line,
                    "answer": None,
                    "points": 2,
                    "metadata": {"source": "uploaded_book", "subject": subject, "unit": unit, "class_name": class_name, "book_title": document.get("title"), "page": document.get("page")},
                })
        return sources

    def train(self, questions: List[Dict[str, Any]]) -> Dict[str, int]:
        existing = {str(item.get("prompt", "")).strip().lower() for item in self.trained}
        added = 0
        skipped = 0
        for raw_question in questions:
            question = self._normalize_training_question(raw_question)
            prompt = str(question.get("prompt", "")).strip()
            if not prompt or prompt.lower() in existing or not self._has_valid_answer(question):
                skipped += 1
                continue
            self.trained.append({**question, "trained": True, "training_status": "teacher_approved"})
            existing.add(prompt.lower())
            added += 1
        self.trained_path.write_text(json.dumps(self.trained, indent=2, ensure_ascii=True), encoding="utf-8")
        return {"added": added, "skipped": skipped}

    def trained_questions(self, subject: str, class_name: str, unit: str, difficulty: str | None = None, limit: int = 50) -> List[Dict[str, Any]]:
        requested_subject = self._scope_value(subject)
        requested_class = self.normalize_class_name(class_name)
        requested_unit = self._scope_value(unit)
        matches = []
        for item in self.trained:
            metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
            if not self._same_scope(metadata.get("subject"), requested_subject):
                continue
            if not self._same_scope(metadata.get("class_name"), requested_class):
                continue
            if not self._same_scope(metadata.get("unit"), requested_unit) and str(metadata.get("unit", "")).lower() != "all units":
                continue
            if difficulty and str(item.get("difficulty", "")).lower() != difficulty.lower():
                continue
            matches.append(item)
        return matches[:max(1, min(limit, 100))]

    def _enrich_trained_scope(self) -> None:
        source_by_prompt = {}
        if self.training_source_path.exists():
            for line in self.training_source_path.read_text(encoding="utf-8").splitlines():
                try:
                    source = json.loads(line)
                except json.JSONDecodeError:
                    continue
                source_by_prompt[self._normalize_prompt(source.get("question", ""))] = source

        changed = False
        existing_prompts = {self._normalize_prompt(item.get("prompt", "")) for item in self.trained}
        for source in source_by_prompt.values():
            normalized = self._normalize_training_question(source)
            prompt = self._normalize_prompt(normalized.get("prompt", ""))
            if not prompt or prompt in existing_prompts or not self._has_valid_answer(normalized):
                continue
            self.trained.append({**normalized, "trained": True, "training_status": "teacher_approved"})
            existing_prompts.add(prompt)
            changed = True

        for item in self.trained:
            metadata = dict(item.get("metadata") or {})
            source = source_by_prompt.get(self._normalize_prompt(item.get("prompt", "")), {})
            fallback_math = str(item.get("id", "")).lower().startswith("q") and str(item.get("id", ""))[1:].isdigit()
            scope = {
                "subject": metadata.get("subject") or item.get("subject") or source.get("subject") or ("Mathematics" if fallback_math else "General Subject"),
                "class_name": metadata.get("class_name") or item.get("class_name") or source.get("class") or ("P1" if fallback_math else "Unknown"),
                "unit": metadata.get("unit") or item.get("unit") or source.get("unit") or ("Unit 1" if fallback_math else "Unassigned"),
            }
            scope["class_name"] = self.normalize_class_name(scope["class_name"]) or scope["class_name"]
            for key, value in scope.items():
                if metadata.get(key) != value or item.get(key) != value:
                    changed = True
                metadata[key] = value
                item[key] = value
            item["metadata"] = metadata
        if changed:
            self.trained_path.write_text(json.dumps(self.trained, indent=2, ensure_ascii=True), encoding="utf-8")

    @staticmethod
    def _scope_value(value: Any) -> str:
        return str(value or "").strip()

    @staticmethod
    def normalize_class_name(value: Any) -> str:
        text = re.sub(r"[^a-z0-9]", "", str(value or "").lower())
        match = re.fullmatch(r"(?:p|primary)(\d+)", text)
        return f"P{match.group(1)}" if match else str(value or "").strip()

    @classmethod
    def _same_scope(cls, actual: Any, requested: str) -> bool:
        actual_str = cls._scope_value(actual).lower()
        requested_str = requested.lower()
        if actual_str == requested_str:
            return True
        if actual_str and requested_str:
            if actual_str in requested_str or requested_str in actual_str:
                return True
        return False

    @staticmethod
    def _normalize_training_question(question: Dict[str, Any]) -> Dict[str, Any]:
        item = dict(question)
        item["prompt"] = str(item.get("question") or item.get("prompt") or "").strip()
        item["type"] = str(item.get("type") or item.get("question_type") or "open_question")
        if not item.get("points") and item.get("total_points"):
            item["points"] = item["total_points"]
        if item.get("answer") is None:
            item["answer"] = item.get("correct_answer") or item.get("expected_answer")
        if item["type"] == "multiple_choice" and isinstance(item.get("answer"), str) and isinstance(item.get("options"), list):
            answer_text = item["answer"].strip().lower()
            for position, option in enumerate(item["options"]):
                if answer_text == str(option).strip().lower():
                    item["answer"] = position
                    break
        if item["type"] == "match" and item.get("answer") is None:
            item["answer"] = item.get("correct_matches")
        if item["type"] == "rearrange" and item.get("answer") is None:
            item["answer"] = item.get("correct_order")
        if item["type"] == "drag_and_drop" and item.get("answer") is None:
            item["answer"] = item.get("correct_answer")
        metadata = dict(item.get("metadata") or {})
        for key in ("country", "curriculum", "level", "class", "class_name", "subject", "unit", "topic", "subtopic", "learning_outcome", "language", "accepted_answers", "marking_scheme", "grading", "grading_method", "correction_engine", "source", "left", "right", "items", "groups", "instruction", "explanation", "total_points"):
            if key in item and key not in metadata:
                metadata["class_name" if key == "class" else key] = item[key]
        item["metadata"] = metadata
        item.pop("question", None)
        item.pop("question_type", None)
        item.pop("correct_answer", None)
        item.pop("expected_answer", None)
        item.pop("correct_matches", None)
        item.pop("correct_order", None)
        return item

    @staticmethod
    def _normalize_prompt(text: str) -> str:
        return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", str(text).lower())).strip()

    def find_trained_answer(self, prompt: str, subject: str | None = None, class_name: str | None = None) -> Dict[str, Any] | None:
        query = str(prompt or "").strip()
        if not query:
            return None

        normalized_query = self._normalize_prompt(query)
        best_match: Dict[str, Any] | None = None
        best_score = -1.0
        for item in self.trained:
            item_prompt = str(item.get("prompt", "")).strip()
            if not item_prompt:
                continue
            item_subject = str(item.get("metadata", {}).get("subject") or item.get("subject") or "").strip()
            item_class = self.normalize_class_name(item.get("metadata", {}).get("class_name") or item.get("class_name"))
            if subject and item_subject and item_subject.lower() != str(subject).lower():
                continue
            if class_name and item_class and item_class.lower() != self.normalize_class_name(class_name).lower():
                continue

            normalized_item = self._normalize_prompt(item_prompt)
            if not normalized_item:
                continue

            if normalized_query == normalized_item:
                score = 1.0
            else:
                query_tokens = set(normalized_query.split())
                item_tokens = set(normalized_item.split())
                if not query_tokens or not item_tokens:
                    score = 0.0
                else:
                    overlap = len(query_tokens & item_tokens) / len(query_tokens | item_tokens)
                    score = overlap

            if score > best_score and score >= 0.75:
                best_score = score
                best_match = item

        if not best_match:
            return None

        answer = best_match.get("answer")
        if answer is None and isinstance(best_match.get("options"), list) and isinstance(best_match.get("correct_index"), int):
            options = best_match.get("options")
            answer = options[best_match["correct_index"]] if 0 <= best_match["correct_index"] < len(options) else None
        if answer is None:
            return None

        metadata = best_match.get("metadata", {}) if isinstance(best_match.get("metadata"), dict) else {}
        return {
            "provider": "trained_dataset",
            "answer": str(answer),
            "sources": [{
                "title": metadata.get("source") or "Teacher-reviewed Q&A",
                "text": best_match.get("prompt"),
                "source_type": "teacher_review",
                "subject": metadata.get("subject") or best_match.get("subject"),
                "unit": metadata.get("unit") or best_match.get("unit"),
            }],
            "verified": True,
            "confidence": "high",
            "matched_prompt": best_match.get("prompt"),
        }

    def train_document(self, text: str, subject: str, unit: str, class_name: str) -> Dict[str, Any]:
        questions = self._parse_question_document(text, subject, unit, class_name)
        result = self.train(questions)
        return {**result, "questions": questions}

    @staticmethod
    def _parse_question_document(text: str, subject: str, unit: str, class_name: str) -> List[Dict[str, Any]]:
        lines = []
        for raw_line in text.splitlines():
            line = re.sub(r"\s+", " ", raw_line).strip()
            if not line:
                continue
            if "|" in line:
                cells = [cell.strip() for cell in line.split("|") if cell.strip()]
                if len(cells) > 1 and re.match(r"^\d+$", cells[0]):
                    lines.append(f"{cells[0]}. {cells[1]}")
                    lines.extend(cells[2:])
                else:
                    lines.extend(cells)
            else:
                lines.append(line)
        parsed = []
        answer_key = {}
        in_answer_key = False
        current = None
        options = []

        def finish():
            nonlocal current, options
            if not current:
                return
            answer = current.get("answer")
            if isinstance(answer, str) and options:
                answer_text = answer.strip().lower()
                if len(answer_text) == 1 and answer_text.isalpha():
                    position = ord(answer_text.upper()) - ord("A")
                    answer = position if 0 <= position < len(options) else answer
                else:
                    for position, option in enumerate(options):
                        if answer_text == option.lower():
                            answer = position
                            break
            current["options"] = options or None
            current["answer"] = answer
            if current.get("prompt"):
                parsed.append(current)
            current = None
            options = []

        for line in lines:
            inline_key = re.match(r"^(?:answer\s*key|answers|ibisubizo)\s*:\s*(.+)$", line, re.I)
            if inline_key:
                for key_number, key_answer in re.findall(r"(\d+)\s*[.):\-]?\s*([A-H])\b", inline_key.group(1), re.I):
                    answer_key[int(key_number)] = key_answer.upper()
                in_answer_key = True
                continue
            if re.match(r"^(answer\s*key|answers|answer|ibisubizo)\s*:?$", line, re.I):
                in_answer_key = True
                continue
            if in_answer_key:
                key_match = re.match(r"^(\d+)\s*[.):\-]?\s*([A-H])\b", line, re.I)
                if key_match:
                    answer_key[int(key_match.group(1))] = key_match.group(2).upper()
                    continue
                if not re.match(r"^\d+\s*[.):\-]", line):
                    in_answer_key = False
            question_match = re.match(r"^(?:question|ikibazo)?\s*(?:q\s*)?(\d+)(?:[.):\-]\s+|\s+)(.+)$", line, re.I)
            labelled_question = re.match(r"^(?:question|ikibazo|q)\s*:\s*(.+)$", line, re.I)
            answer_match = re.match(r"^(?:answer|ans|correct answer|igisubizo(?: nyacyo)?)\s*(?:[:\-]\s*|\s+)(.+)$", line, re.I)
            option_match = re.match(r"^([A-H])[.)\-:]\s*(.+)$", line, re.I)
            if question_match or labelled_question:
                finish()
                current = {"prompt": (question_match or labelled_question).group(2 if question_match else 1), "answer": None, "type": "multiple_choice" if options else "open_question", "points": 1, "difficulty": "medium", "metadata": {"source": "teacher_question_document", "subject": subject, "unit": unit, "class_name": class_name, "training_status": "teacher_approved"}}
            elif answer_match and current:
                current["answer"] = answer_match.group(1).strip()
            elif option_match and current:
                options.append(option_match.group(2).strip())
                current["type"] = "multiple_choice"
            elif current and current.get("answer") is None and len(line) > 2 and line.lower().startswith(("correct:", "solution:")):
                current["answer"] = line.split(":", 1)[1].strip()
        finish()
        for position, question in enumerate(parsed, 1):
            answer = answer_key.get(position)
            if answer and isinstance(question.get("options"), list):
                question["answer"] = ord(answer) - ord("A")
        return parsed

    @staticmethod
    def _has_valid_answer(question: Dict[str, Any]) -> bool:
        answer = question.get("answer")
        if answer is None or answer == "":
            if question.get("type") == "open_question" and (question.get("marking_scheme") or question.get("grading") or question.get("correction_engine")):
                return True
            return False
        options = question.get("options")
        if question.get("type") == "multiple_choice":
            return isinstance(options, list) and len(options) >= 2 and isinstance(answer, int) and 0 <= answer < len(options)
        return True

    @staticmethod
    def _vary_options(question: QuestionModel, index: int) -> None:
        if not isinstance(question.options, list) or len(question.options) < 2:
            return
        original_options = list(question.options)
        order = list(range(len(original_options)))
        random.Random(f"{question.prompt}-{index}").shuffle(order)
        question.options = [original_options[item] for item in order]
        if isinstance(question.answer, int) and 0 <= question.answer < len(original_options):
            question.answer = order.index(question.answer)

    def _bank_for(self, subject: str, unit: str, topic: str, difficulty: str, question_type: str) -> List[Dict[str, Any]]:
        requested_subject = str(subject or "").lower()
        requested_unit = self._scope_value(unit)
        trained = [
            item for item in self.trained
            if item.get("type") == question_type
            and str(item.get("difficulty", difficulty)).lower() == difficulty.lower()
            and str(item.get("metadata", {}).get("subject", subject)).lower() == requested_subject
            and (
                not unit
                or not str(item.get("metadata", {}).get("unit", "")).strip()
                or str(item.get("metadata", {}).get("unit", "")).lower() == "all units"
                or self._same_scope(item.get("metadata", {}).get("unit"), requested_unit)
            )
            and (
                not topic
                or topic.endswith(" activities")
                or not str(item.get("metadata", {}).get("topic", "")).strip()
                or str(item.get("metadata", {}).get("topic", "")).lower() == topic.lower()
            )
        ]
        if trained:
            return trained
        if isinstance(self.advanced, dict):
            advanced_subject = str(self.advanced.get("subject", "")).lower()
            if not advanced_subject or advanced_subject == requested_subject:
                unit_bank = self.advanced.get("units", {}).get(unit, {}).get("assessment_matrix", {}).get(difficulty, {}).get(question_type, [])
                if not unit_bank and unit:
                    for bank_unit, bank_data in self.advanced.get("units", {}).items():
                        if self._same_scope(bank_unit, requested_unit):
                            unit_bank = bank_data.get("assessment_matrix", {}).get(difficulty, {}).get(question_type, [])
                            break
                if unit_bank:
                    return unit_bank
            unit_bank = self.advanced.get(subject, {}).get(topic, {}).get("units", {}).get(unit, {}).get(difficulty, {}).get(question_type, [])
            if unit_bank:
                return unit_bank
            advanced_bank = self.advanced.get(subject, {}).get(topic, {}).get(difficulty, {}).get(question_type, [])
            if advanced_bank:
                return advanced_bank
        level_bank = self.curriculum.get(subject, {}).get(topic, {}).get("levels", {}).get(difficulty, [])
        return level_bank if isinstance(level_bank, list) and question_type == "multiple_choice" else []

    @staticmethod
    def _source(bank: List[Dict[str, Any]], index: int) -> Dict[str, Any]:
        return bank[index % len(bank)] if bank else {}

    @staticmethod
    def _source_metadata(source: Dict[str, Any], default_source: str = "curriculum_dataset") -> Dict[str, Any]:
        metadata = source.get("metadata", {})
        return {"source": metadata.get("source", default_source), **metadata}

    @staticmethod
    def _localize_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
        localized = dict(metadata)
        if localized.get("explanation_rw"):
            localized["explanation"] = localized["explanation_rw"]
        if localized.get("instruction_rw"):
            localized["instruction"] = localized["instruction_rw"]
        localized["output_language"] = "Kinyarwanda"
        return localized

    def _generate_multiple_choice(self, subject: str, topic: str, unit: str, class_name: str | None, index: int, difficulty: str, bank: List[Dict[str, Any]]) -> QuestionModel:
        source = self._source(bank, index)
        prompt = source.get("prompt", f"{subject}, {unit or 'selected unit'}: Which statement best explains {topic}?")
        return QuestionModel(
            id=f"mc-{index + 1}",
            type="multiple_choice",
            prompt=prompt,
            options=source.get("options", ["Correct explanation", "Common misconception", "Unrelated idea", "Incomplete idea"]),
            answer=source.get("answer", 0),
            points=source.get("points", 2),
            difficulty=difficulty,
            metadata={**self._source_metadata(source), "learning_outcome": self._outcome(subject, topic, index)},
        )

    def _generate_match(self, subject: str, topic: str, unit: str, class_name: str | None, index: int, difficulty: str, bank: List[Dict[str, Any]]) -> QuestionModel:
        source = self._source(bank, index)
        return QuestionModel(
            id=f"match-{index + 1}",
            type="match",
            prompt=source.get("prompt", f"Match the correct terms related to {topic} in {unit or 'the selected unit'} of {subject}."),
            options=source.get("options", ["Term A", "Term B", "Term C", "Term D"]),
            answer=source.get("answer", {"left": ["Concept", "Definition"], "right": ["Definition", "Concept"]}),
            points=source.get("points", 2),
            difficulty=difficulty,
            metadata={**self._source_metadata(source), "learning_outcome": self._outcome(subject, topic, index)},
        )

    def _generate_fill_in_gap(self, subject: str, topic: str, unit: str, class_name: str | None, index: int, difficulty: str, bank: List[Dict[str, Any]]) -> QuestionModel:
        source = self._source(bank, index)
        return QuestionModel(
            id=f"fill-{index + 1}",
            type="fill_in_gap",
            prompt=source.get("prompt", f"Complete the sentence about {topic} in {unit or 'the selected unit'}: ________."),
            answer=source.get("answer", "key concept"),
            points=source.get("points", 2),
            difficulty=difficulty,
            metadata={"blank_count": 1, **self._source_metadata(source), "learning_outcome": self._outcome(subject, topic, index)},
        )

    def _generate_rearrange(self, subject: str, topic: str, unit: str, class_name: str | None, index: int, difficulty: str, bank: List[Dict[str, Any]]) -> QuestionModel:
        source = self._source(bank, index)
        return QuestionModel(
            id=f"rearrange-{index + 1}",
            type="rearrange",
            prompt=source.get("prompt", f"Arrange the steps in the correct order for {topic} in {unit or 'the selected unit'}."),
            options=source.get("options", ["Step 1", "Step 2", "Step 3", "Step 4"]),
            answer=source.get("answer", ["Step 1", "Step 2", "Step 3", "Step 4"]),
            points=source.get("points", 3),
            difficulty=difficulty,
            metadata=self._source_metadata(source),
        )

    def _generate_drag_and_drop(self, subject: str, topic: str, unit: str, class_name: str | None, index: int, difficulty: str, bank: List[Dict[str, Any]]) -> QuestionModel:
        source = self._source(bank, index)
        return QuestionModel(
            id=f"drag-{index + 1}",
            type="drag_and_drop",
            prompt=source.get("prompt", f"Drag the correct item to the matching concept for {topic} in {unit or 'the selected unit'}."),
            options=source.get("options", ["Item A", "Item B", "Item C"]),
            answer=source.get("answer", {"target": "Item A", "items": ["Item A", "Item B", "Item C"]}),
            points=source.get("points", 3),
            difficulty=difficulty,
            metadata=self._source_metadata(source),
        )

    def _generate_open_question(self, subject: str, topic: str, unit: str, class_name: str | None, index: int, difficulty: str, bank: List[Dict[str, Any]]) -> QuestionModel:
        source = self._source(bank, index)
        return QuestionModel(
            id=f"open-{index + 1}",
            type="open_question",
            prompt=source.get("prompt", f"Explain how {topic} applies in {unit or 'the selected unit'} of {subject}. Provide examples and justify your answer."),
            answer=source.get("answer"),
            points=source.get("points", 5),
            difficulty=difficulty,
            metadata={"rubric": ["accuracy", "reasoning", "use of examples"], **self._source_metadata(source)},
        )

    def _outcome(self, subject: str, topic: str, index: int) -> str | None:
        outcomes = self.curriculum.get(subject, {}).get(topic, {}).get("learning_outcomes", [])
        return outcomes[index % len(outcomes)] if outcomes else None
