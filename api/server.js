const express = require('express')
const authRouter = require('./auth/auth-router')
const userRouter = require('./users/users-router')

const server = express()

server.use(express.json())

server.use('/api/auth', authRouter)
server.use('/api/users', userRouter)

module.exports = server