const jwt = require('jsonwebtoken')
const env = require('../../.env')

module.exports = (req, res, next) => {
    
    // CORS preflight request: Middleware
    /*
        Faz uma requisição antes da requisição definitiva para checar se o Serviço esta com o CORS habilitado
        para aceitar requisições de origens diferentes.
    */
    if (req.method === 'OPTIONS') {
        next()
    } 
    else {
        /*
            Pega o token que pode vir de 3 lugares:
            - através do request body
            - através de query string
            - através dos headers (cabeçalho)
        */
        const token = req.body.token || req.query.token || req.headers['authorization']
        
        //Verifica se existe token
        if (!token) {
            return res.status(403).send({ errors: ['No token provided.'] })
        }

        //Valida se o token é válido pelo authSecret
        jwt.verify(token, env.authSecret, function (err, decoded) {
            if (err) {
                return res.status(403).send({
                    errors: ['Failed to authenticate token.']
                })
            } 
            else {
                /*
                    Joga o token validado e decodificado para o request: req.decoded = decoded
                    Util quando queremos passar esse token para o próximo middleware da cadeia.
                */
                req.decoded = decoded
                next()
            }
        })
    }
}
