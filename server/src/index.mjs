/**
 * ForSight API — Node.js entry (migration scaffold).
 *
 * Goal: one language (JS/TS) across frontend + backend. The production API still lives in
 * ../backend (Python/FastAPI) until routes are ported here incrementally (auth, projects, jobs,
 * Nessus proxy, file uploads). External CLI tools (nmap, nuclei, …) can be spawned via child_process.
 *
 * Run: cd server && npm install && npm run dev
 * Default port 3001 — set PORT=8000 to mirror uvicorn during cutover.
 */
import Fastify from 'fastify'
import cors from '@fastify/cors'

const app = Fastify({
  logger: true,
})

await app.register(cors, {
  origin: true,
  credentials: true,
})

app.get('/health', async () => ({ ok: true, service: 'forsight-server' }))

app.get('/api/info', async () => ({
  runtime: 'node',
  note: 'Scaffold only — Python backend remains canonical until routes are migrated.',
}))

const port = Number(process.env.PORT || 3001)
const host = process.env.HOST || '0.0.0.0'

await app.listen({ port, host })
app.log.info(`forsight-server listening on http://${host}:${port}`)
