const jwt = require('jsonwebtoken')
const {jwtSecret} = require('../../config/secret')

module.exports = (req, res, next) => {
    const token = req.headers.authorization
    if (token){
        jwt.verify(token, jwtSecret, (err, decodedToken) => {
            if (err) {
                res.status(401).json('valid token required')
            } else {
                req.decodedJwt = decodedToken
                next()
            }
        })
    } else {
        res.status(401).json('token required')
    }
}