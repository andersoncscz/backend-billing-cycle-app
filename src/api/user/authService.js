const _ = require('lodash')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const User = require('./user')
const env = require('../../../.env')

//regex para validar email
const emailRegex = /\S+@\S+\.\S+/
//regex para validar password
const passwordRegex = /((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%]).{6,20})/




const sendErrorsFromDB = (res, dbErrors) => {
    const errors = []
    _.forIn(dbErrors.errors, error => errors.push(error.message))

    //retorna um json com as mensagens de erro
    return res.status(400).json({ errors })
}




const login = (req, res, next) => {

    const email = req.body.email || '' //pega o email do body da requisição
    const password = req.body.password || '' //pega a senha do body da requisição

    //Valida usuário pelo email
    User.findOne({ email }, (err, user) => {
        if (err) { //Retorna erro se houver
            return sendErrorsFromDB(res, err)
        }
        else if (user && bcrypt.compareSync(password, user.password)) { //Compara a senha do usuário passada com a senha do banco criptografada
            //Se a senha esta valida, gera o token utilizando o authSecret do arquivo .env
            const token = jwt.sign(user, env.authSecret, {
                expiresIn: "1 day" //Token será criado com validade de 1 dia.
            })
            //Pega nome e email do usuário via destructing
            const { name, email } = user
            //Retorna um json com o nome, email e o token gerado
            res.json({ name, email, token })

        } else {
            //Retorna um erro ao client
            return res.status(400).send({ errors: ['Usuário/Senha inválidos'] })
        }
    })
}




//Função que valida se o token ainda está valida ou já expirou
const validateToken = (req, res, next) => {

    //Pega o token enviado no request body
    const token = req.body.token || ''
    //Verifica se esta espirado ou não
    jwt.verify(token, env.authSecret, function (err, decoded) {
        return res.status(200).send({ valid: !err })
    })

}





const signup = (req, res, next) => {
    
    //Pega os campos do request body
    const name = req.body.name || ''
    const email = req.body.email || ''
    const password = req.body.password || ''
    const confirmPassword = req.body.confirm_password || ''

    //Verifica se o email bate com a expressão regular definida
    if (!email.match(emailRegex)) {
        return res.status(400).send({ errors: ['O e-mail informa está inválido'] })
    }

    //Verifica se a senha bate com a expressão regular definida
    if (!password.match(passwordRegex)) {
        return res.status(400).send({
            errors: [
                "Senha precisar ter: uma letra maiúscula, uma letra minúscula, um número, uma caractere especial(@#$ %) e tamanho entre 6 - 20."
            ]
        })
    }

    //Gera o Hash do password
    const salt = bcrypt.genSaltSync()
    const passwordHash = bcrypt.hashSync(password, salt)
    
    //Verifica se o password enviado no request body, bate com a senha hash gerada
    if (!bcrypt.compareSync(confirmPassword, passwordHash)) {
        return res.status(400).send({ errors: ['Senhas não conferem.'] })
    }

    //Valida usuário pelo email
    User.findOne({ email }, (err, user) => {
        if (err) { //Retorna erro se houver
            return sendErrorsFromDB(res, err)
        } 
        else if (user) { //Verifica se o usuário já esta cadastrado
            return res.status(400).send({ errors: ['Usuário já cadastrado.'] })
        } 
        else {
            
            //Instancia um novo usuário, com a senha criptografada
            const newUser = new User({ name, email, password: passwordHash })
            //Salva o usuário
            newUser.save(err => {
                if (err) {
                    return sendErrorsFromDB(res, err)
                } else {
                    //Efetua login direto em caso de successo do cadastro, sem redirecionar para a página de login
                    login(req, res, next)
                }
            })
        }
    })
}


module.exports = { login, signup, validateToken }