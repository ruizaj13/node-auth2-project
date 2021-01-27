const router = require('express').Router()
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const { jwtSecret } = require('../../config/secret')
const Users = require('../users/users-model')
const {isValid} = require('../users/users-middleware')

router.post('/register', (req, res) => {
    const credentials = req.body

    if(isValid(credentials)) {
        const hash = bcrypt.hashSync(credentials.password, 10)
        credentials.password = hash

        Users.add(credentials)
            .then(user => {
                res.status(201).json({ data: user })
            })
            .catch(err => {
                res.status(500).json({message: err.message})
            })
    } else {
        res.status(400).json({message: 'provide username and password'})
    }
})

router.post('/login', (req, res) => {
    const {username, password} = req.body

    if (isValid(req.body)) {
        Users.findBy({ username })
            .then(([user]) => {
                if (user && bcrypt.compareSync(password, user.password)) {
                    const token = generateToken(user)
                    res.status(200).json({ message: 'Access Granted', token})
                } else {
                    res.status(401).json({ message: 'invalid credentials' })
                }
            })
            .catch(err => {
                res.status(500).json({ message: err.message })
            })
    } else {
        res.status(400).json({ message: 'provide username and password'})
    }
})

function generateToken(user) {
    const payload = {
        subject: user.id,
        username: user.username,
        department: user.department
    }
    const options = {
        expiresIn: '1h'
    }
    return jwt.sign(payload, jwtSecret, options)
}

module.exports = router