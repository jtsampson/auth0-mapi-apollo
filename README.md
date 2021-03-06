[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# auth0-mapi-apollo

An in-progress, unofficial apollo graphql wrapper for the Auth0 Management API. 

Built for fun and primarily as an exercise in building a rest backed apollo api.
Starting with a strict api version and may migrate to a more ui based schema

I would like to get to a full implementation. If you would like to help out, please see CONTRIBUTING.md.

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Documentation](#documentation)
- [Issues](#issues)
- [Mapping APIS to Query/Mutation](#mapping-apis-to-querymutation)
- [Design Considerations](#design-considerations)
- [License](#license)
- [Contribute](#contribute)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Documentation
* [Auth0 Management API V2](https://auth0.com/docs/api/management/v2)
* [Apollo Graphql](https://www.apollographql.com/)

# Design Considerations

I compiled this list after the fact, so the api does not yet  hold up to these goals. 

- Avoid use of JSON type when possible: if necessary, use and deprecate in liu of 
- TODO: Use Paginated lists by default. 
- Return affected objects as the result of mutation
- Use single input objects for mutations
- Create a schema that closely matches the api (to simplify development), this may change if I later
  target the api towards a UI use case. for instance the Auth0 Dashboard.
- Resolve all scope lists in connections resources (which can be returned as CSV or WSSV strings or arrays) to an array of strings
- Use consistent naming conventions...
  - Actions: Create/Update/Delete
  - Child Types: (type)(type)
  - Enums:  (type)Type
  - Inputs:  Input(type)(action)
  - Types:  Resource Name
  
# Issues
* Testing  the get/update/delete for branding templates requires a paid auth0 plan. 
* Need for pact tests
* Creation of LogStream for Event Grid seems require Azure Account...API complains about resource group name when creating from dashboard,

# Mapping APIS to Query/Mutation

| Resource           | Operation                                              | Query/Mutation                    | 
| :------------------| :----------------------------------------------------- | :-------------------------------- | 
| Branding           | Get branding settings                                  | brandings                         | 
| Branding           | Update branding settings                               | updateBrandings                   | 
| Branding           | Get New Universal Login Experience template            | brandingTemplates                 |
| Branding           | Create/Update New Universal Login Experience template  | updateBrandingTemplates           |
| Branding           | Delete New Universal Login Experience template         | deleteBrandingTemplates           |
| Client Grants      | Get Client Grants                                      | clientGrants, clientGrantsByFilter|         
| Client Grants      | Create Client Grant                                    | createClientGrant                 | 
| Client Grants      | Delete Client Grant                                    | deleteClientGrant                 | 
| Client Grants      | Update Client Grant                                    | updateClientGrant                 | 
| Clients            | Get Clients                                            | clients/clientsByFilter           | 
| Client             | Get Client                                             | client                            |
| Client             | Delete Client                                          | deleteClient                      |
| Client             | Update Client                                          | updateClient                      |
| Client             | Rotate Client Secret                                   | rotateClient                      |
| Connections        | Get All Connections                                    | connections, connectionsByName, connectionsByFilter, connectionsByStrategy |
| Connections        | Create Connection                                      | createConnection                  |
| Connections        | Get a Connection                                       | connection                        | 
| Connections        | Delete a Connection                                    | deleteConnection                  | 
| Connections        | Update a Connection                                    | `TODO`                            | 
| Connections        | Check Connection Status                                | connectionStatus                  |
| Connections        | Delete Connection User                                 | deleteConnectionUser              |
| Custom Domains     | Get Custom Domain Configurations                       | `TODO`                            |
| Custom Domains     | Configure New Custom Domain                            | `TODO`                            |
| Custom Domains     | Get Custom Domain Configuration                        | `TODO`                            |
| Custom Domains     | Delete Custom Domain Configuration                     | `TODO`                            |
| Custom Domains     | Update Custom Domain Configuration                     | `TODO`                            |
| Custom Domains     | Verify Custom Domain Configuration                     | `TODO`                            |
| Device Credentials | Get Device Credentials                                 | deviceCredentialsByFilter         |
| Device Credentials | Create a device public key credential                  | createDeviceCredentials `TODO` (requires access token with create:current_user_device_credentials, not allowed by client_credential grant) |
| Device Credentials | Delete Device Credentials                              | deleteDeviceCredentials           |
| Grants             | Get Grants                                             | grants, grantsByFilter            |
| Grants             | Delete a Grant                                         | deleteGrant                       |
| Hooks              | Get Hooks                                              | hooks, hooksByFilter              |
| Hooks              | Create a Hook                                          | createHook                        |
| Hooks              | Get a Hook                                             | hook                              |
| Hooks              | Delete a Hook                                          | deleteHook                        |
| Hooks              | Update a Hook                                          | updateHook                        |
| Hooks              | Get Hook Secrets                                       | hookSecrets                       |
| Hooks              | Delete Hook Secrets                                    | deleteHookSecrets                 |
| Hooks              | Update Hook Secrets                                    | updateHookSecrets                 |
| Hooks              | Add Hook Secrets                                       | addHookSecrets                    |
| Log Streams        | Get Log Streams                                        | logStreams                        |
| Log Streams        | Create a log Stream                                    | createLogStreamXXX                |
| Log Streams        | Get log stream by ID                                   | logStream                         |
| Log Streams        | Delete log stream                                      | deleteLogStream                   |
| Log Streams        | update log stream                                      | updateLogStreamXXX                |
| Logs               | All                                                    | Not Supported                     |
| Prompts            | All                                                    | Not Supported                     |
| Resource Servers   | Get Resource Servers                                   | apis, apisByFilter                |
| Resource Servers   | Get Resource Server                                    | apiById                           |
| Resource Servers   | Create Resource Server                                 | apiCreate                         |
| Resource Servers   | Update Resource Server                                 | apiUpdate                         |
| Resource Servers   | Delete Resource Server                                 | apiDelete                         |
| Roles              | Get Roles                                              | roles, rolesByFilter              |
| Roles              | Get Role                                               | roleById                          |
| Roles              | Create Role                                            | roleCreate                        |                       
| Roles              | Update Role                                            | roleUpdate                        |                        
| Roles Permissions  | TODO                                                   | roleDelete                        |                       
| Rules              | All                                                    | `TODO`                          |
| Rule Configs       | All                                                    | `TODO`                          |
| User Blocks        | All                                                    | `TODO`                          |
| Users              | All                                                    | `TODO`                          |
| Users By Email     | All                                                    | `TODO`                          |
| Blacklists         | All                                                    | `TODO`                          |
| Email Templates    | All                                                    | `TODO`                          |
| Emails             | All                                                    | `TODO`                          |
| Guardian           | All                                                    | `TODO`                          |
| Jobs               | All                                                    | `TODO`                          |
| Keys               | All                                                    | `TODO`                          |
| Stats              | All                                                    | `TODO`                          |
| Tenants            | All                                                    | `TODO`                          |
| Anomaly            | All                                                    | `TODO`                          |
| Tickets            | All                                                    | `TODO`                          |


# License
 - [LICENSE](./LICENSE)

# Contribute
 - [CONTRIBUTE](./CONTRIBUTING.md)
