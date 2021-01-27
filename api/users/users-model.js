const db = require('../../database/dbConfig')

module.exports = {find, findBy, add, findById}

function find() {
    return db('users').select('id','username', 'department')
}

function findBy(filter) {
    return db('users').where(filter)
}

async function add(user) {
    const [id] = await db('users').insert(user, 'id')
    return findById(id)
}

function findById(id){
    return db('users').where('users.id', id).first()
}