const { GraphQLHexColorCode, Pair, GraphQLJSON, GraphQLJSONObject } = require('./scalars')
const { GraphQLURL } = require('graphql-custom-types')

// ----------------------------
// shared field level resolvers
// ----------------------------

// TODO - perhaps  resolveSetUserAttribute should be changed to a string and be 'on_first_login' and 'on_each_login'
// eslint-disable-next-line camelcase
const resolveSetUserAttribute = ({ set_user_root_attributes = 'dummy' }) => !(set_user_root_attributes === 'on_first_login') // todo  reverse on update.. maybe merge up if all connections have this,
const resolveScopeFromSpaceSeparatedList = ({ scope }) => !scope ? [] : scope.split(' ') // todo how to do the reverse on update?
const resolveScopeFromCommaSeparatedList = ({ scope }) => !scope ? [] : scope.split(',') // todo how to do the reverse on update?
/* eslint-disable camelcase */

const resolvers = {

  AddOnType: {
    AWS: 'aws',
    AZURE_BLOB: 'azure_blob',
    AZURE_SB: 'azure_sb',
    BOX: 'box',
    CLOUDBEES: 'cloudbees',
    CONCUR: 'concur',
    DROPBOX: 'dropbox',
    ECHOSIGN: 'echosign',
    EGNYTE: 'egnyte',
    FIREBASE: 'firebase',
    LAYER: 'layer',
    MSCRM: 'mscrm',
    NEWRELIC: 'newrelic',
    OFFICE365: 'office365',
    RMS: 'rms',
    SALESFORCE: 'salesforce',
    SALESFORCE_API: 'salesforce_api',
    SALESFORCE_SANDBOX_API: 'salesforce_sandbox_api',
    SAMLP: 'samlp',
    SAP_API: 'sap_api',
    SENTRY: 'sentry',
    SHAREPOINT: 'sharepoint',
    SLACK: 'slack',
    SPRINGCM: 'springcm',
    SSO_INTEGRATION: 'sso_integration',
    WAMS: 'wams',
    WSFED: 'wsfed',
    ZENDESK: 'zendesk',
    ZOOM: 'zoom'
  },
  Api: {
    enforce_policies: ({ enforce_policies = false }) => enforce_policies, // default false if not set
    is_system: ({ is_system = false }) => is_system, // default false if not set
    scopes: ({ scopes = [] }) => scopes // default empty
  },
  ApiSigningAlgorythmType: {
    RS256: 'RS256',
    HS256: 'HS256'
  },
  AppType: {
    REGULAR_WEB: 'regular_web',
    SINGLE_PAGE: 'spa',
    MACHINE_TO_MACHINE: 'non_interactive',
    NATIVE: 'native'
  },
  BrandingColors: {
    /* If page_background is a string value, coerce it to an
         * object so we can resolve it to PageBackground and union
         * it with PageBackgroundGradient
         */
    page_background: ({ page_background }) => typeof (page_background) === 'string' ? { color: page_background } : page_background

  },
  BrandingPageBackground: {
    __resolveType (obj, _context, _info) {
      if (obj.color) {
        return 'PageBackgroundColor'
      }

      if (obj.type) {
        return 'PageBackgroundGradient'
      }

      return null
    }
  },
  Connection: {
    // push the strategy to the options object for ConnectionOptions type resolution.
    options: ({ options, strategy }) => {
      options.strategy = strategy
      return options
    }
  },
  ConnectionOptions: {
    __resolveType ({ strategy, name }, _context, _info) {
      switch (strategy) {
        // TODO: can we rewrite this to transform strategy and concetenate, rather than direct mappings - would have to take into account
        // TODO: maybe switching on name for social Social Connections might work insted of strategies
        case 'apple':
          return 'ConnectionOptionsApple'
        case 'amazon':
          return 'ConnectionOptionsAmazon'
        case 'baidu':
          return 'ConnectionOptionsBaidu'
        case 'bitbucket':
          return 'ConnectionOptionsBitBucket'
        case 'box':
          return 'ConnectionOptionsBox'
        case 'dropbox':
          return 'ConnectionOptionsDropBox'
        case 'daccount':
          return 'ConnectionOptionsDAccount'
        case 'dwolla':
          return 'ConnectionOptionsDWolla'
        case 'evernote':
          return 'ConnectionOptionsEvernote'
        case 'evernote-sandbox':
          return 'ConnectionOptionsEvernoteSandbox'
        case 'exact':
          return 'ConnectionOptionsExact'
        case 'facebook':
          return 'ConnectionOptionsFacebook'
        case 'fitbit':
          return 'ConnectionOptionsFitBit'
        case 'github' :
          return 'ConnectionOptionsGitHub'
        case 'line':
          return 'ConnectionOptionsLine'
        case 'linkedin':
          return 'ConnectionOptionsLinkedIn'
        case 'oauth2' :
          return 'ConnectionOptionsOAuth2'
        case 'paypal' :
          return 'ConnectionOptionsPayPal'
        case 'paypal-sandbox' :
          return 'ConnectionOptionsPayPalSandbox'
        case 'planningcenter' :
          return 'ConnectionOptionsPlanningCenter'
        case 'renren' :
          return 'ConnectionOptionsRenRen'
        case 'salesforce':
          return 'ConnectionOptionSalesForce'
        case 'salesforce-sandbox':
          return 'ConnectionOptionSalesForceSandbox'
        case 'salesforce-community':
          return 'ConnectionOptionSalesForceCommunity'
        case 'shopify':
          return 'ConnectionOptionsShopify'
        case 'twitter' :
          return 'ConnectionOptionsTwitter'
        case 'thirtysevensignals':
          return 'ConnectionOptionsThirtySevenSignals' // AKA BaseCamp
        case 'vkontakte' :
          return 'ConnectionOptionsVKontakte'
        case 'weibo' :
          return 'ConnectionOptionsWeibo'
        case 'windowslive':
          return 'ConnectionOptionsWindowsLive'
        case 'wordpress':
          return 'ConnectionOptionsWordPress'
        case 'yahoo':
          return 'ConnectionOptionsYahoo'
        case 'yammer':
          return 'ConnectionOptionsYammer'
        case 'yandex' :
          return 'ConnectionOptionsYandex'
        case 'auth0':
          return 'ConnectionOptionsAuth0'

          // Enterprise Connections
        case 'google-oauth2':
          return 'ConnectionOptionsGoogleOAuth2'
        case 'oidc' :
          return 'ConnectionOptionsOIDC'
        case 'samlp':
          return 'ConnectionOptionsSaml'
        case 'waad':
          return 'ConnectionOptionsWAAD'
        default :
          return null
      }
    }
  },
  // ------------------
  // Social Connections
  // ------------------
  ConnectionOptionsApple: {
    scope: resolveScopeFromSpaceSeparatedList,
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsAmazon: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsBaidu: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsBox: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsDWolla: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsThirtySevenSignals: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsBitBucket: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsDAccount: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsDropBox: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsEvernote: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsEvernoteSandbox: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsExact: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsFacebook: {
    scope: resolveScopeFromCommaSeparatedList,
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsFitBit: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsGitHub: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsLine: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsLinkedIn: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsOAuth2: {
    scope: resolveScopeFromSpaceSeparatedList,
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsPayPal: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsPayPalSandbox: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsPlanningCenter: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsRenRen: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsSalesForce: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsSalesForceCommunity: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsSalesForceSandbox: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsShopify: {
    scope: resolveScopeFromCommaSeparatedList,
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsTwitter: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsVKontakte: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsWeibo: {
    scope: resolveScopeFromCommaSeparatedList,
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsWordPress: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsYahoo: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsYandex: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsYammer: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  // ------------------
  // Enterprise Connections
  // ------------------
  ConnectionOptionsOIDC: {
    scope: resolveScopeFromSpaceSeparatedList,
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsSaml: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionOptionsSamlSignatureAlgorithm: {
    RSA_SHA1: 'rsa-sha1',
    RSA_SHA256: 'rsa-sha256'
  },
  ConnectionOptionsSamlSignatureAlgorithmDigest: {
    SHA1: 'sha1',
    SHA256: 'sha256'
  },
  ConnectionOptionsWAAD: {
    set_user_root_attributes: resolveSetUserAttribute
  },
  ConnectionStatusType: {
    ONLINE: 'online',
    ERROR: 'error'
  },
  ConnectionStrategy: {
    AD: 'ad',
    ADFS: 'adfs',
    AMAZON: 'amazon',
    AOL: 'aol',
    APPLE: 'apple',
    AUTH0: 'auth0',
    AUTH0_ADLDAP: 'auth0-adldap',
    AUTH0_OIDC: 'auth0-oidc',
    BAIDU: 'baidu',
    BITBUCKET: 'bitbucket',
    BITLY: 'bitly',
    BOX: 'box',
    CUSTOM: 'custom',
    DACCOUNT: 'daccount',
    DROPBOX: 'dropbox',
    DWOLLA: 'dwolla',
    EMAIL: 'email',
    EVERNOTE: 'evernote',
    EVERNOTE_SANDBOX: 'evernote-sandbox',
    EXACT: 'exact',
    FACEBOOK: 'facebook',
    FITBIT: 'fitbit',
    FLICKR: 'flickr',
    GITHUB: 'github',
    GOOGLE_APPS: 'google-apps',
    GOOGLE_OAUTH2: 'google-oauth2',
    GUARDIAN: 'guardian',
    INSTAGRAM: 'instagram',
    IP: 'ip',
    LINE: 'line',
    LINKEDIN: 'linkedin',
    MIICARD: 'miicard',
    OAUTH1: 'oauth1',
    OAUTH2: 'oauth2',
    OFFICE365: 'office365',
    OIDC: 'oidc',
    PAYPAL: 'paypal',
    PAYPAL_SANDBOX: 'paypal-sandbox',
    PINGFEDERATE: 'pingfederate',
    PLANNINGCENTER: 'planningcenter',
    RENREN: 'renren',
    SALESFORCE: 'salesforce',
    SALESFORCE_COMMUNITY: 'salesforce-community',
    SALESFORCE_SANDBOX: 'salesforce-sandbox',
    SAMLP: 'samlp',
    SHAREPOINT: 'sharepoint',
    SHOPIFY: 'shopify',
    SMS: 'sms',
    SOUNDCLOUD: 'soundcloud',
    THECITY: 'thecity',
    THECITY_SANDBOX: 'thecity-sandbox',
    THIRTYSEVENSIGNALS: 'thirtysevensignals',
    TWITTER: 'twitter',
    UNTAPPD: 'untappd',
    VKONTAKTE: 'vkontakte',
    WAAD: 'waad',
    WEIBO: 'weibo',
    WINDOWSLIVE: 'windowslive',
    WORDPRESS: 'wordpress',
    YAHOO: 'yahoo',
    YAMMER: 'yammer',
    YANDEX: 'yandex'

  },
  DeviceCredentialType: {
    PUBLIC_KEY: 'public_key',
    REFRESH_TOKEN: 'refresh_token',
    ROTATING_REFRESH_TOKEN: 'rotating_refresh_token'
  },
  ExpirationType: {
    NON_EXPIRING: 'non-expiring'
    // TODO are there more types?
  },
  GrantType: {
    AUTHORIZATION_CODE: 'authorization_code',
    CLIENT_CREDENTIALS: 'client_credentials',
    DEVICE_CODE: 'urn:ietf:params:oauth:grant-type:device_code',
    IMPLICIT: 'implicit',
    MFA_OOB: 'http://auth0.com/oauth/grant-type/mfa-oob',
    MFA_OTP: 'http://auth0.com/oauth/grant-type/mfa-otp',
    MFA_RECOVERY_CODE: 'http://auth0.com/oauth/grant-type/mfa-recovery-code',
    PASSWORD: 'password',
    PASSWORD_REALM: 'http://auth0.com/oauth/grant-type/password-realm',
    REFRESH_TOKEN: 'refresh_token'
  },
  HCC: GraphQLHexColorCode,
  HookTriggerIdType: {
    CREDENTIALS_EXCHANGE: 'credentials-exchange',
    PRE_USER_REGISTRATION: 'pre-user-registration',
    POST_USER_REGISTRATION: 'post-user-registration',
    POST_CHANGE_PASSWORD: 'post-change-password',
    SEND_PHONE_MESSAGE: 'send-phone-message'
  },
  JSON: GraphQLJSON,
  JSONObject: GraphQLJSONObject,
  LogStream: {
    __resolveType ({ type }, context, info) {
      switch (type) {
        case 'datadog' :
          return 'LogStreamDataDog'
        case 'eventbridge':
          return 'LogStreamEventBridge'
        case 'eventgrid' :
          return 'LogStreamSinkEventGrid'
        case 'http' :
          return 'LogStreamWebhook'
        case 'splunk' :
          return 'LogStreamSplunk'
        case 'sumo' :
          return 'LogStreamSumo'
        default :
          return null // GraphQLError is thrown
      }
    }
  },
  LogStreamDataDog: {
    datadogRegion: ({ sink: { datadogRegion } }) => datadogRegion,
    datadogApiKey: ({ sink: { datadogApiKey } }) => datadogApiKey
  },
  LogStreamDataDogRegion: {
    EU: 'eu',
    US: 'us'
  },
  LogStreamEventBridge: {
    awsAccountId: ({ sink: { awsAccountId } }) => awsAccountId,
    awsRegion: ({ sink: { awsRegion } }) => awsRegion,
    awsPartnerEventSource: ({ sink: { awsPartnerEventSource } }) => awsPartnerEventSource
  },
  LogStreamEventGrid: {
    azureSubscriptionId: ({ sink: { azureSubscriptionId } }) => azureSubscriptionId,
    azureResourceGroup: ({ sink: { azureResourceGroup } }) => azureResourceGroup,
    azureRegion: ({ sink: { azureRegion } }) => azureRegion,
    azurePartnerTopic: ({ sink: { azurePartnerTopic } }) => azurePartnerTopic
  },
  LogStreamSplunk: {
    splunkDomain: ({ sink: { splunkDomain } }) => splunkDomain,
    splunkToken: ({ sink: { splunkToken } }) => splunkToken,
    splunkPort: ({ sink: { splunkPort } }) => splunkPort,
    splunkSecure: ({ sink: { splunkSecure } }) => splunkSecure
  },
  LogStreamStatusType: {
    ACTIVE: 'active',
    PAUSED: 'paused',
    SUSPENDED: 'suspended'
  },
  LogStreamType: {
    HTTP: 'http',
    EVENT_BRIDGE: 'eventbridge',
    EVENT_GRID: 'eventgrid',
    SPLUNK: 'splunk',
    DATADOG: 'datadog',
    SUMO: 'sumo'
  },
  LogStreamSumo: {
    sumoSourceAddress: ({ sink: { sumoSourceAddress } }) => sumoSourceAddress
  },
  LogStreamWebhook: {
    httpContentFormat: ({ sink: { httpContentFormat } }) => httpContentFormat,
    httpContentType: ({ sink: { httpContentType } }) => httpContentType,
    httpEndpoint: ({ sink: { httpEndpoint } }) => httpEndpoint,
    httpAuthorization: ({ sink: { httpAuthorization } }) => httpAuthorization
  },
  LogStreamWebhookContentFormat: {
    JSONOBJECT: 'JSONOBJECT',
    JSONARRAY: 'JSONLINES',
    JSONLINES: 'JSONLINES'
  },
  Mutation: {
    apiCreate: (_, { input }, { dataSources }) => dataSources.clients.apiCreate(input),
    apiUpdate: (_, { input }, { dataSources }) => dataSources.clients.apiUpdate(input),
    apiDelete: (_, { id }, { dataSources }) => dataSources.clients.apiDelete(id),
    updateBranding: (_, { patches }, { dataSources }) => dataSources.clients.updateBranding(patches),
    updateBrandingTemplates: (_, { patches }, { dataSources }) => dataSources.clients.updateBrandingTemplates(patches),
    deleteBrandingTemplates: (_, __, { dataSources }) => dataSources.clients.deleteBrandingTemplates(),
    createClient: (_, { name }, { dataSources }) => dataSources.clients.createClient(name),
    updateClient: (_, { id, patches }, { dataSources }) => dataSources.clients.updateClient(id, patches),
    deleteClient: (_, { id }, { dataSources }) => dataSources.clients.deleteClient(id),
    rotateClient: (_, { id }, { dataSources }) => dataSources.clients.rotateClient(id),
    createClientGrant: (_, { clientGrant }, { dataSources }) => dataSources.clients.createClientGrant(clientGrant),
    updateClientGrant: (_, { id, patches }, { dataSources }) => dataSources.clients.updateClientGrant(id, patches),
    deleteClientGrant: (_, { id }, { dataSources }) => dataSources.clients.deleteClientGrant(id),
    createConnection: (_, { connection }, { dataSources }) => dataSources.clients.createConnection(connection),
    deleteConnection: (_, { id }, { dataSources }) => dataSources.clients.deleteConnection(id),
    deleteConnectionUser: (_, { input }, { dataSources }) => dataSources.clients.deleteConnectionUser(input),
    deleteDeviceCredential: (_, { id }, { dataSources }) => dataSources.clients.deleteDeviceCredential(id),
    deleteGrant: (_, { input }, { dataSources }) => dataSources.clients.deleteGrant(input),
    createHook: (_, { input }, { dataSources }) => dataSources.clients.createHook(input),
    deleteHook: (_, { input }, { dataSources }) => dataSources.clients.deleteHook(input),
    updateHook: (_, { input }, { dataSources }) => dataSources.clients.updateHook(input),
    addHookSecrets: (_, { input }, { dataSources }) => dataSources.clients.addHookSecrets(input),
    updateHookSecrets: (_, { input }, { dataSources }) => dataSources.clients.updateHookSecrets(input),
    deleteHookSecrets: (_, { input }, { dataSources }) => dataSources.clients.deleteHookSecrets(input),
    createLogStreamDataDog: (_, { input }, { dataSources }) => dataSources.clients.createLogStream({
      ...input,
      type: 'datadog'
    }),
    createLogStreamEventBridge: (_, { input }, { dataSources }) => dataSources.clients.createLogStream({
      ...input,
      type: 'eventbridge'
    }),
    createLogStreamEventGrid: (_, { input }, { dataSources }) => dataSources.clients.createLogStream({
      ...input,
      type: 'eventgrid'
    }),
    createLogStreamSplunk: (_, { input }, { dataSources }) => dataSources.clients.createLogStream({
      ...input,
      type: 'splunk'
    }),
    createLogStreamSumo: (_, { input }, { dataSources }) => dataSources.clients.createLogStream({
      ...input,
      type: 'sumo'
    }),
    createLogStreamWebhook: (_, { input }, { dataSources }) => dataSources.clients.createLogStream({
      ...input,
      type: 'http'
    }),
    deleteLogStream: (_, { id }, { dataSources }) => dataSources.clients.deleteLogStream(id),
    updateLogStreamDataDog: (_, { input }, { dataSources }) => dataSources.clients.updateLogStream(input),
    updateLogStreamEventBridge: (_, { input }, { dataSources }) => dataSources.clients.updateLogStream(input),
    updateLogStreamEventGrid: (_, { input }, { dataSources }) => dataSources.clients.updateLogStream(input),
    updateLogStreamSplunk: (_, { input }, { dataSources }) => dataSources.clients.updateLogStream(input),
    updateLogStreamSumo: (_, { input }, { dataSources }) => dataSources.clients.updateLogStream(input),
    updateLogStreamWebhook: (_, { input }, { dataSources }) => dataSources.clients.updateLogStream(input),
    roleCreate: (_, { input }, { dataSources }) => dataSources.clients.roleCreate(input),
    roleUpdate: (_, { input }, { dataSources }) => dataSources.clients.roleUpdate(input),
    roleDelete: (_, { input }, { dataSources }) => dataSources.clients.roleDelete(input)
  },
  OIDCChannelType: {
    BACK_CHANNEL: 'back_channel',
    FRONT_CHANNEL: 'front_channel'
  },
  Pair: Pair,

  Query: {
    apiById: (_, { id }, { dataSources }) => dataSources.clients.apiById(id),
    apis: (_, __, { dataSources }) => dataSources.clients.apisByFilter({}),
    apisByFilter: (_, { filter }, { dataSources }) => dataSources.clients.apisByFilter(filter),
    branding: (_, __, { dataSources }) => dataSources.clients.getBranding(),
    brandingTemplates: (_, __, { dataSources }) => dataSources.clients.getBrandingTemplates(),
    client: (_, { id }, { dataSources }) => dataSources.clients.getClient(id),
    clients: (_, __, { dataSources }) => dataSources.clients.getClientsByFilter({}),
    clientsByFilter: (_, { filter }, { dataSources }) => dataSources.clients.getClientsByFilter(filter),
    clientsByName: (_, { name }, { dataSources }) => dataSources.clients.getClientsByName(name),
    clientGrants: (_, __, { dataSources }) => dataSources.clients.getClientGrantsByFilter({}),
    clientGrantsByFilter: (_, { filter }, { dataSources }) => dataSources.clients.getClientGrantsByFilter(filter),
    connections: (_, __, { dataSources }) => dataSources.clients.getConnectionsByFilter({}),
    connectionsByFilter: (_, { filter }, { dataSources }) => dataSources.clients.getConnectionsByFilter(filter),
    connectionsByName: (_, { name }, { dataSources }) => dataSources.clients.getConnectionsByFilter({ name: name }),
    connectionsByStrategy: (_, { strategy }, { dataSources }) => dataSources.clients.getConnectionsByFilter({ strategy: strategy }),
    connection: (_, { id }, { dataSources }) => dataSources.clients.getConnection(id),
    connectionStatus: (_, { id }, { dataSources }) => dataSources.clients.getConnectionStatus(id),
    deviceCredentialsByFilter: (_, { filter }, { dataSources }) => dataSources.clients.getDeviceCredentialsByFilter(filter),
    grantsByFilter: (_, { filter }, { dataSources }) => dataSources.clients.getGrantsByFilter(filter),
    hooks: (_, __, { dataSources }) => dataSources.clients.getHooksByFilter({}),
    hooksByFilter: (_, { filter }, { dataSources }) => dataSources.clients.getHooksByFilter(filter),
    hook: (_, { input }, { dataSources }) => dataSources.clients.getHook(input),
    hookSecrets: (_, { id }, { dataSources }) => dataSources.clients.getHookSecrets(id),
    logStream: (_, { id }, { dataSources }) => dataSources.clients.getLogStream(id),
    logStreams: (_, __, { dataSources }) => dataSources.clients.getLogStreams(),
    roleById: (_, { id }, { dataSources }) => dataSources.clients.rolesById(id),
    roles: (_, __, { dataSources }) => dataSources.clients.rolesByFilter({}),
    rolesByFilter: (_, { filter }, { dataSources }) => dataSources.clients.rolesByFilter(filter),
    rules: (_, __, { dataSources }) => dataSources.clients.getRulesByFilter({}),
    rulesByFilter: (_, { filter }, { dataSources }) => dataSources.clients.getRulesByFilter(filter)

  },
  RotationType: {
    NON_ROTATING: 'non-rotating' // TODO are there more types?
  },
  RuleStage: {
    LOGIN_SUCCESS: 'login_success',
    LOGIN_FAILURE: 'login_failure',
    PRE_AUTHORIZE: 'pre_authorize'
  },
  StrengthLevel: {
    NONE: 'none',
    LOW: 'low',
    FAIR: 'fair',
    GOOD: 'good',
    EXCELLENT: 'excellent'
  },
  TokenDialectType: {
    ACCESS_TOKEN: 'access_token',
    ACCESS_TOKEN_AUTHZ: 'access_token_authz'
  },
  TokenEndpointAuthMethod: {
    BASIC: 'client_secret_basic',
    NONE: 'none',
    POST: 'client_secret_post'
  },
  UniversalLoginExperience: {
    NEW: 'new',
    CLASSIC: 'classic'
  },
  URL: GraphQLURL
}

/* eslint-enable camelcase */
module.exports = { resolvers }
