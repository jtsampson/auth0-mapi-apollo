const { ApolloError, AuthenticationError, ForbiddenError, UserInputError } = require('apollo-server-errors')
const axios = require('axios').default
const app = require('config').get('app')
const tokenProvider = require('axios-token-interceptor')

require('axios-debug-log')({
  request: function (debug, config) {
    debug('Request with ' + config.headers['content-type'])
  },
  response: function (debug, response) {
    debug(
      'Response with ' + response.headers['content-type'],
      'from ' + response.config.url
    )
  },
  error: function (debug, error) {
    // Read https://www.npmjs.com/package/axios#handling-errors for more info
    debug('Boom', error)
  }
})

class Connector {
  constructor () {
    this.api = axios.create({ baseURL: app['base-url'] })
    // this.api.defaults.headers.common['Content-Type'] = 'application/json'
    //
    // const correlationIdProvider = axios.interceptors.request.use(function (config) {
    //   // TODO: add in correlation id strategy similar to 'tokenProvider'
    //   config.headers.headers['X-Correlation-ID'] = 'correlation-id'
    //   return config
    // })
    // this.api.api.interceptors.request.use(correlationIdProvider)
    // TODO : Think about puling this out to it's own file.
    // TODO : add dynamic token caching
    this.api.interceptors.request.use(tokenProvider({
      // getToken: async () => await Promise.resolve({ data: { access_token: 'bad token' } })
      getToken: () => axios
        .post(app['token-url'], {
          audience: app.audience,
          client_id: app['client-id'],
          client_secret: app['client-secret'],
          grant_type: 'client_credentials'
        })
        .then(res => res.data.access_token)
        .then(token => {
          console.log(token)
          return token
        }
        ).catch(function (err) {
          if (err.response) {
            if (err.response.status === 401) {
              throw new AuthenticationError(err.response.data.message)
            }
            console.log(err.response.data)
            console.log(err.response.status)
            console.log(err.response.headers)
          } else if (err.request) {
            console.log(err.request)
          } else {
            // Something happened in setting up the request that triggered an Error
            console.log('Error', err.message)
          }
          console.log(err.config)
        })

    }))

    const isHandlerEnabled = (config = {}) => {
      return !(Object.prototype.hasOwnProperty.call(config, 'handlerEnabled') && !config.handlerEnabled)
    }

    const successHandler = (response) => {
      if (isHandlerEnabled(response.config)) {
        // Handle responses
      }
      return response
    }

    const errorHandler = (err) => {
      if (isHandlerEnabled(err.config)) {
        if (err.response && err.response.status) {
          switch (err.response.status) {
            case 400 :
              throw (new UserInputError(err.response.data.message))
            case 401 :
              throw (new AuthenticationError(err.response.data.message))
            case 403 :
              throw (new ForbiddenError(err.response.data.message))
            case 409 :
              // resource already exists?
              throw (new ForbiddenError(err.response.data.message))
            default:
              throw (new ApolloError(err.response.data.message))
          }
        }
      }
    }

    this.api.interceptors.response.use(
      response => successHandler(response),
      error => errorHandler(error)
    )

    this.patchFilters = {
      // See https://github.com/auth0/auth0-deploy-cli/blob/cc5c4a09df565ff567c3ce7d79098107b9aa99a0/src/readonly.js
      hook: ['id', 'triggerId']
    }
  }

  // -----------------------
  // Branding
  // -----------------------

  /**
   * Get Branding Settings.
   * @returns {Promise<*>}
   * @see https://auth0.com/docs/api/management/v2#!/Branding/get_branding
   */
  getBranding () {
    return this.api.get('/api/v2/branding').then(res => res.data)
  }

  /**
   * Get branding templates.
   * @returns {Promise<*>}
   * @see https://auth0.com/docs/api/management/v2#!/Branding/get_universal_login
   */
  getBrandingTemplates () {
    return this.api.get('/api/v2/branding/templates/universal-login')
      .then(res => { return { universal_login: res.data.body } })
  }

  /**
   * Update branding settings.
   * @param {object} patches - patches - object containing fields to patch
   * @returns {Promise<*>}
   * @see https://auth0.com/docs/api/management/v2#!/Branding/patch_branding
   */
  updateBranding (patches) {
    if (patches.colors && patches.colors.page_background_as_string && patches.colors.page_background_as_gradient) {
      throw new UserInputError('page_background_as_string and page_background_as_gradient are mutually exclusive input')
    }

    return this.api.patch('/api/v2/branding', patches).then(res => res.data)
  }

  /**
   * Update branding templates.
   * @param {object} patches - patches - object containing fields to patch
   * @returns {Promise<*>}
   * @see https://auth0.com/docs/api/management/v2#!/Branding/put_universal_login
   */
  updateBrandingTemplates (patches) {
    const payload = {
      body: patches.universal_login,
      type: 'put_universal-login_body'
    }

    return this.api.patch('/api/v2/branding/templates/universal-login', payload)
      .then(() => this.getBrandingTemplates())
  }

  /**
   * Delete branding templates.
   * @returns {Promise<*>}
   * @see https://auth0.com/docs/api/management/v2#!/Branding/put_universal_login
   */
  deleteBrandingTemplates () {
    return this.api.delete('/api/v2/branding/templates/universal-login')
      .then(() => this.getBrandingTemplates())
  }

  // -----------------------
  // Clients
  // -----------------------

  /**
   * Create a new client (application or SSO integration).
   * Note: save client_id in the response to use for  get/update.
   * @param {string} name - the client alias
   * @returns {Promise<*>}
   * @see https://auth0.com/docs/api/management/v2#!/Clients/post_clients
   */
  createClient (name) {
    return this.api.post('/api/v2/clients', { name: name }).then(res => res.data)
  }

  /**
   * Updates a client.
   * @param {string} id      - id of the client to update
   * @param {object} patches - object containing fields to patch
   * @returns {Promise<*>}
   * @see https://auth0.com/docs/api/management/v2#!/Clients/patch_clients_by_id
   */
  updateClient (id, patches) {
    return this.api.patch(`/api/v2/clients/${id}`, patches).then(res => res.data)
  }

  /**
   * Delete a client and related configuration (rules, connections, etc).
   * @param {string} id - the client_id to delete
   * @returns {Promise<{client_id: *}>}
   * @see https://auth0.com/docs/api/management/v2#!/Clients/delete_clients_by_id
   */
  deleteClient (id) {
    return this.api.delete(`/api/v2/clients/${id}`).then(_res => { return { client_id: id } })
  }

  /**
   * Rotate a client secret ]
   * @param {string} id - the client_id to rotate
   * @returns {Promise<*>}
   * @see https://auth0.com/docs/api/management/v2#!/Clients/post_rotate_secret
   */
  rotateClient (id) {
    return this.api.post(`/api/v2/clients/${id}/rotate-secret`).then(res => res.data)
  }

  /**
   * Retrieve client details.
   * @param {string} id - the client_id to get
   * @returns {Promise<*>}
   * @see https://auth0.com/docs/api/management/v2#!/Clients/get_clients_by_id
   */
  getClient (id) {
    return this.api.get(`/api/v2/clients/${id}`).then(res => res.data)
  }

  /**
   * Retrieve clients (applications and SSO integrations) matching provided filters.
   * @param {object}  filter={}               - If empty, no filter applied, gets all clients/pages
   * @param {string}  filter.[app_type]       - Optional filter by a comma-separated list of application types.
   * @param {boolean} filter.[is_first_party] - Optional filter on whether or not a client is a first-party client.
   * @param {boolean} filter.[is_global]      - Optional filter on the global client parameter.
   * @param {number}  filter.[page]           - Page index of the results to return. First page is 0.
   * @param {number}  filter.[per_page]       - Number of results per page. Paging is disabled if not set.
   * @returns {Promise<*>}
   * @see https://auth0.com/docs/api/management/v2#!/Clients/get_clients
   */
  getClientsByFilter (filter) {
    filter = this.mungeClientFilter(filter)
    return this.api.get('/api/v2/clients', { params: filter }).then(res => res.data)
  }

  /**
   * Gets a client by name (alias).
   * @param {string} name - the client name to get.
   * @returns {Promise<AxiosResponse<any>>}
   */
  async getClientsByName (name) {
    return this.api.get('/api/v2/clients').then(res => res.data.filter(client => client.name === name))
  }

  // -------------------------
  // Client Grants
  // -----------------------
  /**
   * Create a client grant.
   * @param {object} clientGrant            - The client grant
   * @param {string} clientGrant.client_id  - ID of the client.
   * @param {string} clientGrant.audience   - Audience or API identifier of this client grant.
   * @param {string[]} clientGrant.scope    - Scopes allowed for this client grant.
   * @returns {Promise<*>}
   * @see https://auth0.com/docs/api/management/v2#!/Client_Grants/post_client_grants
   */
  createClientGrant (clientGrant) {
    return this.api.post('/api/v2/clients', clientGrant).then(res => res.data)
  }

  /**
   * Updates a client grant.
   * @param {string} id      - id of the client grant to update
   * @param {object} patches - object containing fields to patch
   * @returns {Promise<*>}
   * @see https://auth0.com/docs/api/management/v2#!/Client_Grants/patch_client_grants_by_id
   */
  updateClientGrant (id, patches) {
    return this.api.patch(`/api/v2/clients/${id}`, patches).then(res => res.data)
  }

  /**
   * Delete a client grant
   * @param {string} id - the id to delete
   * @returns {Promise<{client_id: *}>}
   * @see https://auth0.com/docs/api/management/v2#!/Client_Grants/delete_client_grants_by_id
   */
  deleteClientGrant (id) {
    return this.api.delete(`/api/v2/clients/${id}`).then(_res => { return { id: id } })
  }

  /**
   * Gets client grants.
   * @param {object} filter={}          - if empty, no filter applied, gets all client grants/pages
   * @param {string} filter.[audience]  - filter on audience
   * @param {string} filter.[client_id] - filter on client_id
   * @param {number} filter.[page]      - page index of the results to return. First page is 0
   * @param {number} filter.[per_page]  - number of results per page. Paging is disabled if not set
   * @returns {Promise<*>}
   */
  getClientGrantsByFilter (filter) {
    filter = filter || {}
    return this.api.get('/api/v2/client-grants', { params: filter }).then(res => res.data)
  }

  // -------------------------
  // Connections
  // -----------------------

  /**
   * Creates a new connection based on the connection passed.
   * @param {object} connection          - the new connection
   * @param {string} connection.name     - name of the new connection
   * @param {string} connection.strategy - strategy of the new connection
   * @returns {Promise<*>}
   * @see https://auth0.com/docs/api/management/v2#!/Connections/post_connections
   */
  createConnection (connection) {
    return this.api.post('/api/v2/connections', connection).then(res => res.data)
  }

  /**
   *
   * Gets connections.
   * @param {object} filter={}          - if empty, no filter applied, gets all client grants/pages
   * @param {string} filter.[strategy]  - the strategy filter
   * @param {string} filter.[name]      - the name filter
   * @param {number} filter.[page]      - page index of the results to return. First page is 0
   * @param {number} filter.[per_page]  - number of results per page. Paging is disabled if not set
   * @returns {Promise<*>}
   * @see https://auth0.com/docs/api/management/v2#!/Connections/get_connections
   */
  getConnectionsByFilter (filter) {
    filter = filter || {}
    return this.api.get('/api/v2/connections', { params: filter }).then(res => res.data)
  }

  /**
   * Retrieve connection details.
   * @param {string} id - the connection id to get
   * @returns {Promise<*>}
   * @see https://auth0.com/docs/api/management/v2#!/Connections/get_connections_by_id
   */
  getConnection (id) {
    return this.api.get(`/api/v2/connections/${id}`).then(res => res.data)
  }

  /**
   * Retrieves the status of an ad/ldap connection referenced by its ID.
   * @param {string} id - the connection id to get
   * @returns {Promise<*>}
   * @see https://auth0.com/docs/api/management/v2#!/Connections/get_status
   */
  getConnectionStatus (id) {
    return this.api.get(`/api/v2/connections/${id}/status`)
      .then(_res => {
        return {
          status: 'online',
          message: 'OK'
        }
      }).catch((err) => {
        if (err.name === 'UserInputError') {
          return {
            status: 'error',
            message: err.message
          }
        }
      })
  }

  /**
   * Delete a connection Deletes a connection and all its users.
   * @param {string} id - the connection id to delete
   * @returns {Promise<{client_id: *}>}
   * @see https://auth0.com/docs/api/management/v2#!/Connections/delete_connections_by_id
   */
  deleteConnection (id) {
    return this.api.delete(`/api/v2/connections/${id}`).then(_res => { return { id: id } })
  }

  /**
   * Deletes a specified connection user by its email (you cannot delete all users from specific connection).
   * Currently, only Database Connections are supported.
   * @param {object} input - the input object
   * @param {string} input.id - the the connection id
   * @param {string} input.email - the user to delete identified by email.
   * @returns {Promise<{client_id: *}>}
   * @see https://auth0.com/docs/api/management/v2#!/Connections/delete_users_by_email
   */
  deleteConnectionUser (input) {
    return this.api.delete(`/api/v2/connections/${input.id}/users`, { params: { email: input.email } })
      .then(_res => { return { id: input.id, email: input.email } })
  }

  /**
   * Retrieve device credential details for a given user_id.
   * Note: Device Credentials APIs are designed for ad-hoc administrative use only, and paging is by default
   *       enabled.
   * Note: When Refresh Token Rotation is enabled, the endpoint becomes eventual consistent.
   * @param {object}  filter={}               - If empty, no filter applied, gets all clients/pages
   * @param {string}  filter.[user_id]        - Optional filter by user_id of the devices to retrieve.
   * @param {boolean} filter.[client_id]      - Optional filter on client_id of the devices to retrieve.
   * @param {boolean} filter.[type]           - Optional filter on Type of credentials to retrieve. Must
   *                                                be`public_key`, `refresh_token` or `rotating_refresh_token`.
   *                                                The property will default to `refresh_token` when paging
   *                                                is requested
   * @param {number}  filter.[page]           - Page index of the results to return. First page is 0.
   * @param {number}  filter.[per_page]       - Number of results per page. Paging is disabled if not set.
   * @returns {Promise<*>}
   * @see https://auth0.com/docs/api/management/v2#!/Clients/get_clients
   */
  getDeviceCredentialsByFilter (filter) {
    return this.api.get('/api/v2/device-credentials', { params: filter }).then(res => res.data)
  }

  /**
   * Delete a device credential.
   * @param {string} id - the device credential to delete (  regex ^dcr_[A-Za-z0-9]{16}$ )
   * @returns {Promise<{client_id: *}>}
   * @see https://auth0.com/docs/api/management/v2#!/Device_Credentials/delete_device_credentials_by_id
   */
  deleteDeviceCredential (id) {
    // TODO in stead of passing back id as a confirm, we could do success fail, or get actual to delete, then passit back after 204, but that could expose and atach
    return this.api.delete(`/api/v2/device-credentials/${id}`).then(_res => { return { id: id } })
  }

  /**
   * Retrieve the grants associated with your account.
   * @param {object} filter={}          - if empty, no filter applied, gets all client grants/pages
   * @param {string} filter.[user_id]   - the id of the user to delete grants for
   * @param {string} filter.[client_id] - the id of the client to delete grants for
   * @param {string} filter.[audience]  - the audience to delete grants for
   * @param {number} filter.[page]      - page index of the results to return. First page is 0
   * @param {number} filter.[per_page]  - number of results per page. Paging is disabled if not set
   * @returns {Promise<*>}
   * @see https://auth0.com/docs/api/management/v2#!/Grants/get_grants
   */
  getGrantsByFilter (filter) {
    return this.api.get('/api/v2/grants', { params: filter }).then(res => res.data)
  }

  /**
   * Delete a grant associated with your account.
   * @param {string} id - the grant id
   * @returns {Promise<{id: *}>}
   * @see https://auth0.com/docs/api/management/v2#!/Grants/delete_grants_by_id
   */
  deleteGrant (input) {
    // TODO: should we check for 204?
    return this.api.delete('/api/v2/grants', { params: input }).then(_res => input)
  }

  /**
   * Retrieve all hooks.
   * @param {object} filter={}          - if empty, no filter applied, gets all hooks
   * @param {string} filter.[enabled]   - filter on whether a hook is enabled (true) or disabled (false).
   * @param {string} filter.[triggerId] - filter on trigger id (matching)
   * @param {number} filter.[page]      - page index of the results to return. First page is 0
   * @param {number} filter.[per_page]  - number of results per page. Paging is disabled if not set
   * @returns {Promise<*>}
   * https://auth0.com/docs/api/management/v2#!/Hooks/get_hooks
   */
  getHooksByFilter (filter) {
    return this.api.get('/api/v2/hooks', { params: filter }).then(res => res.data)
  }

  /**
   * Create a new hook.
   * @param {object} hook              - the hook
   * @param {string} hook.enabled      - hook (true) enabled, (false) disabled
   * @param {string} hook.name         - hook name
   * @param {string} hook.triggerId    - hook trigger id
   * @param {json}   hook.dependencies - the hook metadata as stringified json
   * @returns {Promise<*>}
   * @see https://auth0.com/docs/api/management/v2#!/Hooks/post_hooks
   */
  createHook (hook) {
    return this.api.post('/api/v2/hooks', hook).then(res => res.data)
  }

  /**
   * Retrieve a hook by its ID.
   * @param {object} hook              - the hook
   * @param {string} hook.id           - the hook id
   * @returns {Promise<AxiosResponse<any>>}
   * @see https://auth0.com/docs/api/management/v2#!/Hooks/get_hooks_by_id
   */
  getHook (hook) {
    return this.api.get(`/api/v2/hooks/${hook.id}`).then(res => res.data)
  }

  /**
   * Delete a hook.
   * @param {object} hook  - the hook
   * @param {string} hook.id  - the hook id to delete
   * @returns {Promise<{id: *}>}
   * @see https://auth0.com/docs/api/management/v2#!/Hooks/delete_hooks_by_id
   */
  deleteHook (hook) {
    // In general the delete API returns a 204 whether or not the hook id exists, so this always outputs the input
    return this.api.delete(`/api/v2/hooks/${hook.id}`).then(() => { return hook })
  }

  /**
   * Update a hook.
   * @param {object} hook              - the hook
   * @param {string} hook.id           - the hook id
   * @param {string} hook.enabled      - hook (true) enabled, (false) disabled
   * @param {string} hook.name        - hook name
   * @param {string} hook.triggerId    - hook trigger id
   * @param {json}   hook.dependencies - the hook metadata as stringified json
   * @returns {Promise<AxiosResponse<any>>}
   * @see https://auth0.com/docs/api/management/v2#!/Hooks/delete_hooks_by_id
   */
  updateHook (hook) {
    const patch = this.omit(hook, this.patchFilters.hook)
    return this.api.patch(`/api/v2/hooks/${hook.id}`, patch).then(res => res.data)
  }

  // TODO: fix this, it's not pretty.
  mungeClientFilter (filter) {
    filter = filter || {}
    if (filter.app_type) {
      filter.app_type = filter.app_type.join(',')
    }
    return filter
  }

  omit (obj, props) {
    props = props instanceof Array ? props : [props]
    // eslint-disable-next-line no-eval
    return eval(`(({${props.join(',')}, ...o}) => o)(obj)`)
  }
}

module.exports = Connector
