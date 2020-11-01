const {originUrl} = require("./config")

const {
	JSDOM
} = require("jsdom");;
const {
	window
} = new JSDOM(``, {
	url: originUrl,
	runScripts: "dangerously"
});
// server side `$` XD
const $ = require('jquery')(window);

const requests = async (url, method) => {
	let result = ""
	try {
		result = await $.ajax({
			url: url,
			type: method,
		})
	} catch (err) {
		console.log("[x] errors")
		console.log(err)
		result = {
			data: ""
		}
	}

	return result.data
}

exports.requests = requests
