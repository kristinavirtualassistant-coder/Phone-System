const shutdown = () => process.exit(0);
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
console.log('worker integration ready');
setInterval(() => undefined, 60_000);
