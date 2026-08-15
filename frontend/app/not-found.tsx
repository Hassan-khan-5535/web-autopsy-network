export default function NotFound() {
  return (
    <main className="grid min-h-screen place-items-center bg-[#08110f] px-6 text-[#ecf4ee]">
      <section className="max-w-md rounded-2xl border border-emerald-100/10 bg-black/20 p-8 text-center">
        <p className="font-mono text-sm tracking-[0.2em] text-emerald-300/80">404 · UNKNOWN</p>
        <h1 className="mt-4 text-3xl font-semibold tracking-tight">Route not found</h1>
        <p className="mt-3 text-sm leading-6 text-emerald-50/60">This foundation exposes only the landing interface and backend health integration.</p>
      </section>
    </main>
  );
}
