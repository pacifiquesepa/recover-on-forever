import { CalendarDays, Flame, Image as ImageIcon, PlayCircle, Search, X } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import ClientNavbar from './ClientNavbar';
import ClientFooter from './ClientFooter';
import api from '../../lib/api';

const fallback = [
    { id: 'sample-1', title: 'Learning with purpose', category: 'news', description: 'Building confident young learners through curiosity, discipline and care.', photoUrl: null, videoUrl: null, eventDate: '2026-08-01' },
];

export default function NewsPage({ language, onLanguageChange, onLogin, onNavigate, t }) {
    const [items, setItems] = useState([]);
    const [query, setQuery] = useState('');
    const [category, setCategory] = useState('all');
    const [selected, setSelected] = useState(null);
    const [error, setError] = useState('');

    useEffect(() => {
        let active = true;
        api.get('/news').then(({ data }) => active && setItems(data.news || [])).catch(() => active && setError('News is temporarily unavailable.'));
        return () => { active = false; };
    }, []);

    const source = items.length ? items : fallback;
    const categories = ['all', ...new Set(source.map((item) => item.category).filter(Boolean))];
    const visible = useMemo(() => source.filter((item) => (
        (category === 'all' || item.category === category)
        && `${item.title} ${item.description} ${item.category}`.toLowerCase().includes(query.toLowerCase())
    )), [source, category, query]);
    const totalViews = source.reduce((sum, item) => sum + Number(item.views || item.viewCount || 0), 0);
    const totalComments = source.reduce((sum, item) => sum + Number(item.comments || item.commentCount || 0), 0);

    return <div className="min-h-screen bg-[#f7f9fc] text-slate-800">
        <ClientNavbar language={language} onLanguageChange={onLanguageChange} onLogin={onLogin} onNavigate={onNavigate} t={t} />
        <main className="pt-[72px]">
            <section className="relative overflow-hidden bg-[linear-gradient(115deg,#1d2d36_0%,#0e2748_54%,#09285c_100%)] px-5 pb-36 pt-20 text-white sm:px-8 lg:pb-40 lg:pt-24">
                <div className="absolute inset-0 opacity-20" style={{ backgroundImage: 'radial-gradient(#8aa1bb 1px, transparent 1px)', backgroundSize: '38px 38px' }} />
                <div className="relative mx-auto max-w-7xl">
                    <span className="inline-flex items-center gap-3 rounded-full border border-white/15 bg-white/10 px-5 py-2.5 text-xs font-extrabold uppercase tracking-wider text-slate-100"><span className="text-yellow-300">▣</span> News &amp; updates</span>
                    <h1 className="mt-8 max-w-5xl font-display text-5xl font-extrabold leading-[1.02] tracking-tight sm:text-7xl">Latest <span className="text-[#ffc400]">News &amp; Updates</span> from Forever King Academy</h1>
                    <p className="mt-8 max-w-3xl text-base leading-8 text-slate-300 sm:text-lg">Discover announcements, school milestones, learning activities and stories from the Forever King Academy community.</p>
                    <p className="mt-8 text-sm font-bold text-slate-300">Home <span className="px-2 text-slate-500">›</span> <span className="text-[#ffc400]">News</span></p>
                </div>
            </section>

            <section className="relative z-10 mx-auto -mt-24 max-w-7xl px-5 sm:px-8">
                <div className="grid overflow-hidden rounded-3xl border border-slate-100 bg-white p-6 shadow-[0_20px_55px_rgba(22,58,105,.12)] sm:grid-cols-3 lg:grid-cols-5 lg:p-8">
                    <Stat value={source.length} label="Published" />
                    <Stat value={categories.length - 1} label="Categories" />
                    <Stat value={totalViews} label="Total views" />
                    <Stat value={totalComments} label="Comments" />
                    <Stat value={0} label="This week" accent />
                </div>
            </section>

            <section className="mx-auto max-w-7xl px-5 pb-10 pt-12 sm:px-8 lg:pt-16">
                <div className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm lg:p-8">
                    <h2 className="flex items-center gap-3 font-display text-xl font-extrabold text-[#142b4d]"><Search size={23} className="text-[#1557b0]" /> Find News</h2>
                    <div className="mt-7 grid gap-4 lg:grid-cols-[1.3fr_1fr_1fr_1fr_auto]">
                        <label className="block"><span className="mb-2 block text-xs font-extrabold uppercase tracking-wide text-[#142b4d]">Search</span><span className="flex items-center gap-3 rounded-xl border border-slate-200 px-4 py-3"><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Title, content, reference..." className="min-w-0 flex-1 bg-transparent text-sm outline-none" /><Search size={17} className="text-slate-400" /></span></label>
                        <label className="block"><span className="mb-2 block text-xs font-extrabold uppercase tracking-wide text-[#142b4d]">Category</span><select value={category} onChange={(event) => setCategory(event.target.value)} className="w-full rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm outline-none"><option value="all">All categories</option>{categories.slice(1).map((item) => <option key={item} value={item}>{item}</option>)}</select></label>
                        <label className="block"><span className="mb-2 block text-xs font-extrabold uppercase tracking-wide text-[#142b4d]">Reference</span><input placeholder="e.g. FK/NW" className="w-full rounded-xl border border-slate-200 px-4 py-3 text-sm outline-none" /></label>
                        <label className="block"><span className="mb-2 block text-xs font-extrabold uppercase tracking-wide text-[#142b4d]">Sort by</span><select className="w-full rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm outline-none"><option>Most recent</option><option>Most read</option></select></label>
                        <button type="button" className="self-end rounded-xl bg-[#1557b0] px-6 py-3 text-sm font-extrabold text-white transition hover:bg-[#0f438c]" onClick={() => setQuery(query.trim())}><Search size={16} className="mr-2 inline" />Search</button>
                    </div>
                </div>
            </section>

            <section className="mx-auto max-w-7xl px-5 pb-20 sm:px-8 lg:pb-28">
                <div className="flex items-center justify-between gap-4"><div className="flex items-center gap-4"><span className="grid h-12 w-12 place-items-center rounded-2xl bg-red-50 text-red-500"><Flame size={24} fill="currentColor" /></span><h2 className="font-display text-3xl font-extrabold text-[#142b4d]">Trending Now</h2><span className="rounded-full bg-red-500 px-4 py-2 text-xs font-extrabold uppercase tracking-wide text-white">Most read</span></div><span className="hidden text-sm font-semibold text-slate-400 sm:block">{Math.min(source.length, 3)} Hot Stories</span></div>
                {error && <p className="mt-6 rounded-xl bg-amber-50 px-4 py-3 text-sm text-amber-800">{error}</p>}
                <div className="mt-8 grid gap-7 md:grid-cols-2 lg:grid-cols-3">{visible.map((item) => <NewsCard key={item.id} item={item} onOpen={() => setSelected(item)} />)}</div>
                {!visible.length && <div className="py-20 text-center text-sm text-slate-500">No news matched your search.</div>}
            </section>
        </main>
        <ClientFooter />
        {selected && <NewsModal item={selected} onClose={() => setSelected(null)} />}
    </div>;
}

function Stat({ value, label, accent }) { return <div className="flex items-center justify-center border-slate-200 px-4 py-4 text-center [&+div]:border-l"><div><strong className={`block font-display text-4xl font-extrabold ${accent ? 'text-red-500' : 'text-[#1557b0]'}`}>{value}</strong><span className="mt-1 block text-xs font-extrabold uppercase tracking-wider text-slate-400">{label}</span></div></div>; }
function NewsCard({ item, onOpen }) { const photoUrl = safeMediaUrl(item.photoUrl); const date = formatDate(item.eventDate || item.createdAt); return <article className="overflow-hidden rounded-3xl border border-slate-200 bg-white shadow-sm transition duration-300 hover:-translate-y-1 hover:shadow-xl"><MediaPreview item={item} /><div className="p-6"><span className="inline-block rounded-full bg-[#ffc400] px-4 py-2 text-[11px] font-extrabold uppercase tracking-wide text-[#142b4d]">{item.category || 'News'}</span><h3 className="mt-5 line-clamp-2 font-display text-2xl font-extrabold leading-tight text-[#142b4d]">{item.title}</h3><p className="mt-4 line-clamp-3 text-sm leading-7 text-slate-500">{item.description}</p><div className="mt-6 flex items-center gap-2 text-sm font-semibold text-slate-400"><CalendarDays size={17} className="text-[#1557b0]" />{date}</div><button type="button" onClick={onOpen} className="mt-6 inline-flex items-center gap-2 rounded-xl bg-[#1557b0] px-6 py-3.5 text-sm font-extrabold text-white transition hover:bg-[#0f438c]">Read News <span aria-hidden="true">→</span></button></div></article>; }
function formatDate(value) { if (!value) return 'Date not available'; const date = new Date(value); return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }); }
function safeMediaUrl(value) { if (typeof value !== 'string') return ''; const media = value.trim(); if (/^https?:\/\//i.test(media) || media.startsWith('/uploads/')) return media; const match = media.match(/^data:image\/[a-z0-9.+-]+;base64,([a-z0-9+/=\s]+)$/i); if (!match) return ''; const payload = match[1].replace(/\s/g, ''); if (!payload || payload.length % 4 === 1 || !/^[a-z0-9+/]*={0,2}$/i.test(payload)) return ''; try { atob(payload); } catch { return ''; } return `${media.slice(0, media.indexOf(',') + 1)}${payload}`; }
function MediaPreview({ item }) { const photoUrl = safeMediaUrl(item.photoUrl); return <div className="relative h-60 overflow-hidden bg-[#dcefee]">{photoUrl ? <img src={photoUrl} alt={item.title} className="h-full w-full object-cover transition duration-500 hover:scale-105" /> : <div className="grid h-full place-items-center text-[#1557b0]"><ImageIcon size={42} /></div>}{item.videoUrl && <span className="absolute right-4 top-4 grid h-10 w-10 place-items-center rounded-full bg-white/90 text-[#1557b0] shadow"><PlayCircle size={22} /></span>}</div>; }
function NewsModal({ item, onClose }) { const photoUrl = safeMediaUrl(item.photoUrl); const videoUrl = safeMediaUrl(item.videoUrl); return <div className="fixed inset-0 z-[60] flex items-center justify-center bg-slate-950/70 p-4" role="dialog" aria-modal="true"><article className="max-h-[90vh] w-full max-w-3xl overflow-y-auto rounded-3xl bg-white shadow-2xl"><div className="flex items-center justify-between border-b border-slate-100 p-6"><div><span className="text-xs font-extrabold uppercase tracking-wider text-[#1557b0]">{item.category || 'News'}</span><h2 className="mt-2 font-display text-2xl font-extrabold text-[#142b4d]">{item.title}</h2></div><button onClick={onClose} aria-label="Close" className="rounded-lg p-2 text-slate-400 hover:bg-slate-100"><X size={20} /></button></div><div className="p-6 sm:p-8">{photoUrl && <img src={photoUrl} alt={item.title} className="max-h-[420px] w-full rounded-2xl object-cover" />}{videoUrl && <video src={videoUrl} controls className="mt-4 max-h-[420px] w-full rounded-2xl bg-black" />}{!photoUrl && !videoUrl && <div className="grid h-40 place-items-center rounded-2xl bg-cyan-50 text-[#1557b0]"><ImageIcon size={42} /></div>}<p className="mt-7 whitespace-pre-line text-base leading-8 text-slate-600">{item.description}</p></div></article></div>; }
