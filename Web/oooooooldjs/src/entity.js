const {
	requests
} = require('./util')

class Data {
	constructor(id, block) {
		this.id = id
		this.block = block
	}
}

class DataRepository {
	constructor() {
		this.types = []
		this.datas = []
	}
	C(type, data) {
		this.types.push(type)
		this.datas.push(data)
	}
	U(id, data) {
		for (const index in this.datas) {
			if (this.datas[index].id === id) {
				if (this.types[index] === 'url') {
					// not allow to update url `block`
					return {}
				} else {
					this.datas[index] = data
					return data
				}

			}
		}
	}
	R(id) {
		for (const index in this.datas) {
			if (this.datas[index].id === id) {
				return [this.types[index], this.datas[index]]
			}
		}
	}
	D(id) {
		let di, dt
		for (const index in this.datas) {
			if (this.datas[index].id === id) {
				dt = this.types[index]
				this.types.splice(index, 1)
				di = index
			}
		}
		if (dt === 'url') {
			requests(this.datas[di].block, "DELETE").finally(() => {
				this.datas = this.datas.filter((value) => value.id !== id)
			})
		} else {
			this.datas = this.datas.filter((value) => value.id !== id)
		}
	}
}
const dataRepo = new DataRepository()

exports.Data = Data
exports.DataRepository = DataRepository
