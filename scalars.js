const { Factory } = require('graphql-custom-types')
const { GraphQLScalarType } = require('graphql')
const { GraphQLJSON, GraphQLJSONObject } = require('graphql-type-json')

const Pair = new GraphQLScalarType({
  name: 'Pair',
  description: 'Pair custom scalar type',
  parseValue (data) {
    // data from the apollo client
    if (data === undefined || data === null) {
      return null
    }
    return data.reduce(function (result, item) {
      result[item.key] = item.value
      return result
    }, {})
  },
  serialize (data) {
    return Object.keys(data).map((key) => ({ key, value: data[key] })) // data from the client
  }

})

const factory = new Factory()
const Auth0DeviceCredentialID = factory.getRegexScalar({
  name: 'Auth0DeviceCredentialID',
  regex: /^dcr_[A-Za-z0-9]{16}$/,
  description: 'Auth0DeviceCredentialID represents and Auth0 Device ID',
  error: `Query error: Not a valid Auth0 Device Credential ID, should match pattern: ${this.regex}`
})
const Auth0ConnectionID = factory.getRegexScalar({
  name: 'Auth0DeviceConnectionID',
  regex: /^con_[A-Za-z0-9]{16}$/,
  description: 'Auth0DeviceCredentialID represents and Auth0 Connection ID',
  error: `Query error: Not a valid Auth0 connection ID, should match pattern: ${this.regex}`
})
const Auth0LogStreamID = factory.getRegexScalar({
  name: 'Auth0DeviceConnectionID',
  regex: /^lst_[A-Za-z0-9]{16}$/,
  description: 'Auth0DeviceCredentialID represents and Auth0 Connection ID',
  error: `Query error: Not a valid Auth0 connection ID, should match pattern: ${this.regex}`
})
const Auth0RoleID = factory.getRegexScalar({
  name: 'Auth0DeviceConnectionID',
  regex: /^rol_[A-Za-z0-9]{16}$/,
  description: 'Auth0DeviceCredentialID represents and Auth0 Connection ID',
  error: `Query error: Not a valid Auth0 connection ID, should match pattern: ${this.regex}`
})
const GraphQLHexColorCode = factory.getRegexScalar({
  name: 'HCC',
  regex: /^#([a-fA-F0-9]{6}|[a-fA-F0-9]{3})$/i,
  description: 'The HCC scalar type represents hexadecimal color codes',
  error: `Query error: Not a valid hexadecimal color code, should match pattern: ${this.regex}`
})
module.exports = {
  Auth0ConnectionID, // TODO use or not use, API already validates
  Auth0DeviceCredentialID, // TODO use or not use, API already validates
  Auth0LogStreamID, // TODO use or not use, API already validates
  Auth0RoleID, // TODO use or not use, API already validates
  GraphQLHexColorCode,
  GraphQLJSON,
  GraphQLJSONObject,
  Pair
}
