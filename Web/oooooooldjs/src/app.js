const express = require("express")
const app = express()
const {
	body,
	validationResult
} = require('express-validator')
const {
	v4: uuidv4,
} = require("uuid")

const {
	Data,
	DataRepository
} = require('./entity')
const {
	requests
} = require('./util')
const {
	originUrl,
	host,
    port
} = require('./config')

const dataRepo = new DataRepository()

dataRepo.C("text", new Data("fake-uuid", "canary"))
dataRepo.C("url", new Data("another-fake-uuid", `${originUrl}/data/fake-uuid`))

const middlewares = [
	// should be
	body('*').trim(),
	body('type').if(body('type').exists()).bail().isIn(['url', 'text'])
	.withMessage("type must be `url` or `text`"),
	body('block').if(body('type').exists()).notEmpty()
	.withMessage("no `block` content").bail()
	.if(body('type').isIn(['url'])).isURL({
		require_tld: false
	})
	.custom((value, {
		req
	}) => new URL(value).host === host)
	.withMessage("invalid url!"),
	(req, res, next) => {
		const errors = validationResult(req)
		if (!errors.isEmpty()) {
			return res.status(400).json({
				errors: errors.array()
			})
		}
		next()
	}
]

app.use(express.urlencoded({
	extended: true
}));
app.use(express.json())
app.use(middlewares)

app.get("/data/:id", async (req, res) => {
	const id = req.params.id
	const result = dataRepo.R(id)
	let ret

	if (!result) {
		return res.status(404).send({
			success: 'false',
			message: 'data not found',
		})
	} else {
		if (result[0] === 'url') {
			console.log(result)
			ret = await requests(result[1].block, "GET")
		} else {
			ret = result[1].block
		}
		return res.status(200).send({
			success: "true",
			message: "data found",
			data: ret,
		})
	}
})

app.get("/", (req, res) => {
	console.log(Object.prototype)
    console.log(req.body)
	return res.status(200).send({
		success: "true",
		message: "It works!",
		data: dataRepo
	});
});

app.post("/data", (req, res) => {
	const type = req.body.type ? req.body.type : 'text'
	const block = req.body.block ? req.body.block : ''
	const data = new Data(uuidv4(), block)
	dataRepo.C(type, data)
	return res.status(201).send({
		success: "true",
		message: "data added!",
		data,
	})
})

app.put("/data/:id", (req, res) => {
	const id = req.params.id
	const block = req.body.block ? req.body.block : ''
	const data = new Data(id, block)
	const updated = dataRepo.U(id, data)

	return res.status(201).send({
		success: 'true',
		message: 'updated data',
		updated
	})
})

app.delete("/data/:id", (req, res) => {
	const id = req.params.id

	dataRepo.D(id)
	return res.status(201).send({
		success: 'true',
		message: 'deleted'
	});
})


app.listen(port, () => {
	console.log(`server listening on ${port}`);
});
