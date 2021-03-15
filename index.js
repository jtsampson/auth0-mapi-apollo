const express = require('express')
const Connector = require('./connector')
const { typeDefs } = require('./schema')
const { resolvers } = require('./resolvers')
const { ApolloServer } = require('apollo-server-express')

const server = new ApolloServer({
  typeDefs,
  resolvers,
  dataSources: () => {
    return {
      clients: new Connector()
    }
  },
  context: () => {
    return {
      foo: 'bar'
      // cid: new Guid()
    }
  }
})

const app = express()
server.applyMiddleware({ app })

const port = process.env.PORT || 4000
app.listen({ port: `${port}` }, () =>
  console.log(`🚀 Server ready at http://localhost:${port}${server.graphqlPath}`))
