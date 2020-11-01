
const port = 8888
const originUrl = `http://localhost:${port}`
const host = new URL(originUrl).host
exports.host = host
exports.originUrl = originUrl
exports.port = port