const express = require('express')
const auth = require('./auth')

module.exports = function (server) {
    /*
    * Rotas protegidas por Token JWT
    */
    const protectedApi = express.Router()
    server.use('/api', protectedApi)
    protectedApi.use(auth) //Aplica o Midleware para usar o filtro de autenticação utilizando JWT
    const BillingCycle = require('../api/billingCycle/billingCycleService')
    BillingCycle.register(protectedApi, '/billingCycles') //Registra a rota protegida

    /*
    * Rotas abertas sem JWT
    */
    const openApi = express.Router()
    server.use('/oapi', openApi) //prefixo "oapi" de 'open api'
    const AuthService = require('../api/user/AuthService')
    openApi.post('/login', AuthService.login) //Rota de login
    openApi.post('/signup', AuthService.signup) //Rota de registrar-se
    openApi.post('/validateToken', AuthService.validateToken) //Rota de validação do token
}