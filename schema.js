const { gql } = require('apollo-server-express')

const typeDefs = gql`

  # ------------------
  # enums 
  # ------------------
  enum AddOnType {
    AWS
    AZURE_BLOB
    AZURE_SB
    BOX
    CLOUDBEES
    CONCUR
    DROPBOX
    ECHOSIGN
    EGNYTE
    FIREBASE
    LAYER
    MSCRM
    NEWRELIC
    OFFICE365
    RMS
    SALESFORCE
    SALESFORCE_API
    SALESFORCE_SANDBOX_API
    SAMLP
    SAP_API
    SENTRY
    SHAREPOINT
    SLACK
    SPRINGCM
    SSO_INTEGRATION
    WAMS
    WSFED
    ZENDESK
    ZOOM
  }
  
  enum ApiSigningAlgorythmType {
    RS256
    HS256
  }

  enum AppType {
    MACHINE_TO_MACHINE # non_interactive
    NATIVE # native
    REGULAR_WEB # regular_web
    SINGLE_PAGE # spa
  }

  enum ConnectionOptionsSamlSignatureAlgorithm {
    RSA_SHA1
    RSA_SHA256
  }

  enum ConnectionOptionsSamlSignatureAlgorithmDigest {
    SHA1
    SHA256
  }

  enum ConnectionStatusType {
    ONLINE
    ERROR
  }
  enum ConnectionStrategy {
    AD
    ADFS
    AMAZON
    AOL
    APPLE
    AUTH0
    AUTH0_ADLDAP
    AUTH0_OIDC
    BAIDU
    BITBUCKET
    BITLY
    BOX
    CUSTOM
    DACCOUNT
    DROPBOX
    DWOLLA
    EMAIL
    EVERNOTE
    EVERNOTE_SANDBOX
    EXACT
    FACEBOOK
    FITBIT
    FLICKR
    GITHUB
    GOOGLE_APPS
    GOOGLE_OAUTH2
    GUARDIAN
    INSTAGRAM
    IP
    LINE
    LINKEDIN
    MIICARD
    OAUTH1
    OAUTH2
    OFFICE365
    OIDC
    PAYPAL
    PAYPAL_SANDBOX
    PINGFEDERATE
    PLANNINGCENTER
    RENREN
    SALESFORCE
    SALESFORCE_COMMUNITY
    SALESFORCE_SANDBOX
    SAMLP
    SHAREPOINT
    SHOPIFY
    SMS
    SOUNDCLOUD
    THECITY
    THECITY_SANDBOX
    THIRTYSEVENSIGNALS # BaseCamp
    TWITTER
    UNTAPPD
    VKONTAKTE
    WAAD
    WEIBO
    WINDOWSLIVE
    WORDPRESS
    YAHOO
    YAMMER
    YANDEX
  }

  enum DeviceCredentialType {
    PUBLIC_KEY
    REFRESH_TOKEN
    ROTATING_REFRESH_TOKEN
  }
  
  enum PROMPT {
    COMMON #: 'common'
    CONSENT #: 'consent'
    DEVICE_FLOW #: 'device-flow'
    EMAIL_OTP_CHALLENGE #: 'email-otp-challenge'
    EMAIL_VERIFICATION #: 'email-verification'
    INVITATAION #: 'invitation'
    LOGIN #: 'LOGIN # : 'login'
    LOGIN_ID #: 'login-id'
    LOGIN_EMAIL #: 'login-email-verification'
    LOGIN_PASSWORD #: 'login-password'
    MFA #: 'mfa'
    MFA_EMAIL#: 'mfa-email'
    MFA_OTP #: 'mfa-otp'
    MFA_PHONE #: 'mfa-phone'
    MFA_PUSH #: 'mfa-push'
    MFA_RECOVERY #: 'mfa-recovery-code'
    MFA_SMS #: 'mfa-sms'
    MFA_VOICE #: 'mfa-voice'
    MFA_WEBAUTHN #: 'mfa-webauthn'
    ORGANIZATIONS #: 'organizations'
    RESET_PASSWORDS #: 'reset-password'
    SIGNUP #: 'signup'
    SIGNUP_ID #: 'signup-id'
    SIGN_UP_PASSWORD #: 'signup-password'
    STATUS #: 'status'
  }

  enum ExpirationType {
    NON_EXPIRING

  }

  enum GrantType {
    AUTHORIZATION_CODE
    CLIENT_CREDENTIALS
    DEVICE_CODE #urn:ietf:params:oauth:grant-type:device_code.
    IMPLICIT
    MFA_OOB # http://auth0.com/oauth/grant-type/mfa-oob, 
    MFA_OTP #http://auth0.com/oauth/grant-type/mfa-otp, 
    MFA_RECOVERY_CODE #http://auth0.com/oauth/grant-type/mfa-recovery-code, 
    PASSWORD
    PASSWORD_REALM # http://auth0.com/oauth/grant-type/password-realm, 
    REFRESH_TOKEN
  }

  enum HookTriggerIdType {
    CREDENTIALS_EXCHANGE,
    PRE_USER_REGISTRATION,
    POST_USER_REGISTRATION,
    POST_CHANGE_PASSWORD,
    SEND_PHONE_MESSAGE
  }

  enum LogStreamDataDogRegion {
    EU,
    US
  }

  enum LogStreamType {
    HTTP
    EVENT_BRIDGE
    EVENT_GRID
    SPLUNK
    DATADOG
    SUMO cx
  }

  enum LogStreamStatusType {
    ACTIVE,
    PAUSED,
    SUSPENDED
  }

  enum LogStreamWebhookContentFormat {
    JSONOBJECT,
    JSONARRAY
    JSONLINES
  }

  enum OIDCChannelType {
    BACK_CHANNEL
    FRONT_CHANNEL
  }

  enum RotationType {
    NON_ROTATING
  }

  enum StrengthLevel {
    EXCELLENT
    FAIR
    GOOD
    LOW
    NONE
    BASIC
  }
  
  enum TokenDialectType {
    ACCESS_TOKEN       # : 'access_token'
    ACCESS_TOKEN_AUTHZ #: 'access_token_authz'
  }

  enum TokenEndpointAuthMethod {
    NONE
    POST
    BASIC
  }
  
  enum UniversalLoginExperience {
    NEW
    CLASSIC
  }

  # ------------------
  # inputs 
  # ------------------

  input ApiByFilterInput {
    page : Int
    per_page : Int
  }

  input ApiCreateInput {
    #required
    name: String!
    identifier: String!
    signing_alg: ApiSigningAlgorythmType!
    #optional
    allow_offline_access: Boolean
    client: JSON       # not sure what this is.
    enforce_policies: Boolean
    scopes: [ApiScopeInput]
    signing_secret: String
    skip_consent_for_verifiable_first_party_clients: Boolean
    token_dialect:  TokenDialectType
    token_lifetime: Int
    token_lifetime_for_web: Int
  }

  input ApiUpdateInput {
    # identifier not allowed on update should check on is_xyz
    id: ID!
    #optional
    allow_offline_access: Boolean
    client: JSON       # not sure what this is.
    enforce_policies: Boolean
    name: String
    scopes: [ApiScopeInput]
    signing_alg: ApiSigningAlgorythmType
    signing_secret: String
    skip_consent_for_verifiable_first_party_clients: Boolean
    token_dialect:  TokenDialectType
    token_lifetime: Int
    token_lifetime_for_web: Int
  }

  input ApiScopeInput{
    description: String
    value: String
  }

  input BrandingColorsUpdateInput {
    primary : HCC
    page_background_as_string : HCC
    page_background_as_gradient :BrandingPageBackgroundGradientUpdateInput
  }

  input BrandingFontUpdateInput {
    url : URL
  }

  input BrandingPageBackgroundGradientUpdateInput  {
    type: String
    start:  HCC
    end: HCC
    angle_deg: Int
  }

  input BrandingTemplatesUpdateInput {
    universal_login : String
  }

  input BrandingUpdateInput {
    colors: BrandingColorsUpdateInput
    favicon_url : URL
    font : BrandingFontUpdateInput
    logo_url: URL
    # templates: BrandingTemplatesUpdateInput
  }

  input ClientsByFilterInput {
    app_type : [AppType] # Note: this rest api expects comma seperated list of values.
    is_first_party : Boolean
    is_global : Boolean
    page : Int
    per_page : Int
  }

  input ClientDeleteInput {
    client_id : String
  }

  input ClientUpdateInput {
    # TODO: How to handle "Additional Properties Not Allowed Error" 
    # TODO: Are these just RO properties or are there certain properties 
    # TODO: that can't be combined for a patch?
    # The following properties are read only on client? (additional properties not allowed)
    # client_id
    # callback_url_template
    # global
    # signing_keys
    # tenant

    # alphabetic below
    allowed_clients : [String]
    allowed_logout_urls : [URL]
    allowed_origins: [String] #TODO Check this may be a commas seperated list. 
    app_type: String
    callbacks : [URL]
    client_secret: String
    client_metadata : Pair
    cross_origin_auth: Boolean
    custom_login_page_on: Boolean
    encrypted: Boolean
    grant_types: [GrantType]
    is_first_party: Boolean
    is_token_endpoint_ip_header_trusted: Boolean
    jwt_configuration   : ClientUpdateJWTConfigurationInput
    name: String
    oidc_conformant: Boolean
    sso_disabled: Boolean
  }

  input ClientUpdateJWTConfigurationInput  {
    lifetime_in_seconds: Int
    secret_encoded: Boolean!
  }

  input ClientGrantsByFilterInput {
    audience : String
    client_id : ID
    page : Int
    per_page : Int
  }

  input ClientGrantCreateInput {
    audience : String
    client_id : ID
    scope: [String]
  }

  input ClientGrantUpdateInput {
    audience : String
    client_id : ID
    scope: String
  }

  input ConnectionByFilterInput {
    name : String
    strategy : ConnectionStrategy
    page : Int
    per_page : Int
  }

  input ConnectionCreateInput {
    name: String!
    strategy: ConnectionStrategy!
  }

  input ConnectionUserDeleteInput {
    id: ID!
    email: String
  }

  input DeviceCredentialsByFilterInput {
    user_id: String!
    client_id: String
    type: String
    page : Int
    per_page : Int
  }

  input GrantsByFilterInput {
    user_id : String
    client_id : String
    audience : String
    page : Int
    per_page : Int
  }

  input GrantDeleteInput {
    id : String
    user_id : String
  }

  input HookCreateInput {
    name: String!
    enabled: Boolean
    triggerId: HookTriggerIdType!
    script: String
    dependencies: JSON
  }

  input HooksByFilterInput {
    triggerID : HookTriggerIdType
    enabled :Boolean
    page : Int
    per_page : Int
  }
  
  # TODO is UpdateSigningKeysUpdateInput used?
  input UpdateSigningKeysUpdateInput {
    cert: String
    pkcs7: String
    subject: String
  }

  input DeviceCredentialPublicKeyCreateInput {
    # TODO
    id: ID!
  }

  input HookInput {
    id: ID!
    triggerId: HookTriggerIdType!
    name: String!
    enabled: Boolean,
    script: String
    dependencies: JSON
  }

  input LogStreamDataDogCreateInput {
    name: String!
    # sink data
    datadogRegion: LogStreamDataDogRegion!
    datadogApiKey: String!  # looks like a 10 char mixed case string
  }
  
  input LogStreamDataDogUpdateInput {
    id: ID!
    name: String
    status: LogStreamStatusType
    # sink data
    datadogRegion: LogStreamDataDogRegion
    datadogApiKey: String
  }
  
  input LogStreamDeleteInput {
    id : ID!
  }

  input LogStreamEventBridgeCreateInput {
    name: String!
    # logstream specific
    awsAccountId: String!,  # AWS account ID: 12 digit number
    awsRegion: String!,     # AWS Regions, don't want to put this in ENUM, "us-east-2"
  }

  input LogStreamEventBridgeUpdateInput {
    id: ID!
    name: String
    status: LogStreamStatusType
    # API toes not allow sink data nupdate for event bridge
  }

  input LogStreamEventGridCreateInput {
    name: String!
    # sink data
    azureSubscriptionId: String!,  # Subscription ID: GUID 
    azureResourceGroup: String!,   # Azure-Logs
    azureRegion: String!          # 
    #azurePartnerTopic: String!     #  Generated
  }

  input LogStreamEventGridUpdateInput {
    id: ID!
    name: String
    status: LogStreamStatusType
    # API toes not allow sink data nupdate for event grid
  }

  input LogStreamSplunkCreateInput {
    name: String!
    # sink data
    splunkDomain: String!,  # The domain name of your Splunk instance with an HTTP Event Collector enabled.
    splunkToken: String!,   # Your Splunk event collector token. A guid
    splunkPort: Int!,       # Default is 8088
    splunkSecure: Boolean!  # Verify TLS Toggle in UI: true 
  }
  
  input LogStreamSplunkUpdateInput {
    id: ID!
    name: String
    status: LogStreamStatusType
    # sink data
    splunkDomain: String,
    splunkToken: String,
    splunkPort: Int,
    splunkSecure: Boolean
  }
  
  input LogStreamSumoCreateInput{
    name: String!
    # sink data
    sumoSourceAddress: URL
  }

  input LogStreamSumoUpdateInput{
    id: ID!
    name: String
    status: LogStreamStatusType
    # sink data
    sumoSourceAddress: URL
  }

  input LogStreamWebhookCreateInput {
    name: String!
    # sink data
    httpContentFormat: LogStreamWebhookContentFormat!,
    httpContentType: String!,     # Content Type e.g. application/json
    httpEndpoint: URL!,           # Payload URL, e.g https://path.to.api/webhooks/incomming
    httpAuthorization: String!    # Authorization Token
  }

  input LogStreamWebhookUpdateInput {
    id: ID!
    name: String!
    status: LogStreamStatusType!
    # sink data
    httpContentFormat: LogStreamWebhookContentFormat!,
    httpContentType: String!,
    httpEndpoint: URL!,
    httpAuthorization: String!
  }
  
  input HookSecretsAddInput {
    id: ID!
    secrets: Pair!
  }

  input HookSecretsDeleteInput {
    id: ID!
    keys: [String]!
  }

  input HookSecretsUpdateInput {
    id: ID!
    secrets: Pair!
  }

  input RoleByFilterInput {
    name_filter : String # case insensitive search on name
    page : Int
    per_page : Int
  }

  input RoleCreateInput{
    name: String!,
    description: String!
  }

  input RoleDeleteInput{
    id: ID!
  }
  
  input RoleUpdateInput{
    id: ID!
    name: String,
    description: String
  }

  # ------------------
  # types 
  # ------------------
  type Branding {
    colors: BrandingColors
    favicon_url : URL
    font : BrandingFont
    logo_url: URL
  }

  type BrandingColors {
    primary : HCC
    page_background : BrandingPageBackground
  }

  type BrandingFont {
    url : URL
  }

  type BrandingTemplates {
    universal_login : String
  }
  
  type Client{
    client_id: ID!
    # alphabetic below

    addons : ClientAddOns
    allowed_clients : [String]
    allowed_logout_urls : [URL]
    allowed_origins: [String] # TODO Maybe use URL?
    app_type: AppType
    callback_url_template: Boolean!
    callbacks : [URL]
    client_aliases: [String]
    client_metadata : Pair # TODO or perhaps JSON?
    client_secret: String # only available with grant
    cross_origin_auth: Boolean
    cross_origin_loc: URL
    custom_login_page: String
    custom_login_page_on: Boolean!
    custom_login_page_preview: String
    description : String
    #encrypted: Boolean #TODO is this used?
    encryption_key : ClientEncryptionKey
    form_template : String
    global: Boolean!
    grant_types: [GrantType]!
    initiate_login_uri : String
    is_first_party: Boolean!
    is_token_endpoint_ip_header_trusted: Boolean
    jwt_configuration   : ClientJWTConfiguration
    logo_uri : URL
    mobile : ClientMobile
    name: String!
    # native_social_Logins # TODO 
    oidc_conformant: Boolean!
    refresh_token : ClientRefreshToken
    signing_keys: ClientSigningKeys
    sso: Boolean
    sso_disabled: Boolean
    tenant: String!
    token_endpoint_auth_method : TokenEndpointAuthMethod
    web_origins : [String]
  }

  type ClientAddOns{
    aws : JSON
    azure_blob : JSON
    azure_sb : JSON
    box : JSON
    cloudbees : JSON
    concur : JSON
    dropbox: JSON
    echosign : JSON
    egnyte : JSON
    firebase : JSON
    layer : JSON
    mscrm : JSON
    newrelic : JSON
    office365 : JSON
    rms : JSON
    salesforce : JSON
    salesforce_api : JSON
    salesforce_sandbox_api : JSON
    samlp : JSON
    sap_api : JSON
    sentry : JSON
    sharepoint : JSON
    slack : JSON
    springcm : JSON
    sso_integration : JSON
    wams : JSON
    wsfed : JSON
    zendesk : JSON
    zoom : JSON
  }

  type ClientEncryptionKey {
    pub: String
    cert: String
    subject:String
  }

  type ClientJWTConfiguration  {
    lifetime_in_seconds: Int
    secret_encoded: Boolean!
    #TODO add scopes?
    #scopes: {}, 
    alg:String # TODO could be ENUM 'HS256' or 'RS256'
  }
  
  type ClientMobile {
    android : ClientMobileAndroid
    ios : ClientMobileIOS
  }

  type ClientMobileAndroid{
    app_package_name: String
    sha256_cert_fingerprints : [String]
  }
  
  type ClientMobileIOS {
    team_id: String
    app_bundle_identifier :String
  }

  type ClientRefreshToken {
    expiration_type: ExpirationType
    idle_token_lifetime : Int
    infinite_idle_token_lifetime: Boolean
    infinite_token_lifetime: Int
    leeway: Int
    rotation_type: RotationType
    token_lifetime: Int
  }

  type ClientSigningKeys {
    cert: String
    pkcs7: String
    subject: String
  }

  type ClientGrant {
    id : ID!
    audience: String
    client_id : ID!
    scope: [String]
  }

  type Connection {
    id : ID!
    enabled_clients : [String]!
    is_domain_connection: Boolean
    metadata : Pair # not sure how to do this....unless it is key value like client metdata, may be enterprise connestion related or SAML connectio and may have to move.
    name: String
    options : ConnectionOptions
    provisioning_ticket_url : URL # TODO this may be just a enterprise or SAML connection thing.
    realms : [String]!
    strategy : ConnectionStrategy
  }

  type ConnectionStatus {
    status : ConnectionStatusType
    message : String
  }

  # ------------------
  # Social Connections
  # ------------------
  type ConnectionOptionsApple {
    scope: [String]! # scope is stored as a white space seperated string
    client_id:String
    app_secret: String
    set_user_root_attributes: Boolean
    # Additional Properties
    email: Boolean,
    kid: String,
    name: Boolean,
    team_id:String
  }

  type ConnectionOptionsAmazon {
    scope: [String]! # comes from server as array of strings
    profile: Boolean
    client_id: String
    client_secret: String
    set_user_root_attributes: Boolean
    # Additional Properties
    postal_code: Boolean
  }

  type ConnectionOptionsBaidu {
    scope: [String]!
    profile: Boolean
    client_id: String
    client_secret: String
    set_user_root_attributes: Boolean
  }

  type ConnectionOptionsBitBucket {
    profile: Boolean
    client_id: String
    client_secret: String
    set_user_root_attributes: Boolean

  }

  type ConnectionOptionsBox {
    profile: Boolean
    client_id: String
    client_secret: String
    set_user_root_attributes: Boolean
  }

  type ConnectionOptionsDAccount {
    profile: Boolean
    client_id: String
    client_secret: String
    set_user_root_attributes: Boolean
  }

  type ConnectionOptionsOAuth2 {
    scope: [String]! # this is returned by api as a single string e,g, scope: "read" but we'll convert to array.
    client_id: String
    client_secret: String
    set_user_root_attributes: Boolean

    #additional properties
    authorizationURL: URL
    icon_url: URL
    integration_name: String
    scripts: ConnectionOptionsDigitalOceanScripts
    tokenURL: URL
  }


  type ConnectionOptionsDigitalOceanScripts {
    # TODO will there be other scripts?
    fetchUserProfile : String
  }

  type ConnectionOptionsDWolla {
    scope: [String]!
    client_id: String
    client_secret: String
    set_user_root_attributes: Boolean
    # additional Properties
    AccountInfoFull: Boolean
    Balance: Boolean
    Contacts: Boolean
    Funding: Boolean
    ManageAccount: Boolean
    Request: Boolean
    Send: Boolean
    Transactions: Boolean
    scopeSeparator: String

  }

  type ConnectionOptionsDropBox {
    profile: Boolean
    client_id: String
    client_secret: String
    set_user_root_attributes: Boolean
  }

  type ConnectionOptionsEvernote {
    profile: Boolean
    client_id: String
    client_secret: String
    set_user_root_attributes: Boolean
  }

  type ConnectionOptionsEvernoteSandbox {
    profile: Boolean
    client_id: String
    client_secret: String
    set_user_root_attributes: Boolean
  }

  type ConnectionOptionsExact {
    profile: Boolean
    client_id: String
    client_secret: String
    set_user_root_attributes: Boolean
    # additional properteis
    baseUrl: URL

  }

  type ConnectionOptionsFacebook {
    scope: [String]! # TODO  scope is stored as a csv string in auth0
    client_id: String
    client_secret: String
    set_user_root_attributes: Boolean
    #additional properties
    ads_management: Boolean
    ads_read: Boolean
    allow_context_profile_field: Boolean
    business_management: Boolean
    email: Boolean
    groups_access_member_info: Boolean
    leads_retrieval: Boolean
    manage_notifications: Boolean
    manage_pages: Boolean
    pages_manage_cta: Boolean
    pages_manage_instant_articles: Boolean
    pages_messaging: Boolean
    pages_messaging_phone_number: Boolean
    pages_messaging_subscriptions: Boolean
    pages_show_list: Boolean
    public_profile: Boolean
    publish_actions: Boolean
    publish_pages: Boolean
    publish_to_groups: Boolean
    publish_video: Boolean
    read_audience_network_insights: Boolean
    read_insights: Boolean
    read_mailbox: Boolean
    read_page_mailboxes: Boolean
    read_stream: Boolean
    user_age_range: Boolean
    user_birthday: Boolean
    user_events: Boolean
    user_friends: Boolean
    user_gender: Boolean
    user_groups: Boolean
    user_hometown: Boolean
    user_likes: Boolean
    user_link: Boolean
    user_location: Boolean
    user_managed_groups: Boolean
    user_photos: Boolean
    user_posts: Boolean
    user_status: Boolean
    user_tagged_places: Boolean
    user_videos: Boolean
  }

  type ConnectionOptionsFitBit {
    scope: [String]!
    profile: Boolean
    client_id: String
    client_secret: String,
    set_user_root_attributes: Boolean
    # additional properties
    activity: Boolean
    heartrate: Boolean
    location: Boolean
    nutrition: Boolean
    protocol: String
    settings: Boolean
    sleep: Boolean
    social: Boolean
    weight: Boolean
  }

  type ConnectionOptionsGitHub {
    scope: [String]! # this is passed as array of strings from server
    profile: Boolean
    client_id: String,
    client_secret: String
    set_user_root_attributes: Boolean
    # additional Properties
    admin_org: Boolean
    admin_public_key: Boolean
    admin_repo_hook: Boolean
    delete_repo: Boolean
    email: Boolean
    follow: Boolean
    gist: Boolean
    notifications: Boolean
    public_repo: Boolean
    read_org: Boolean
    read_public_key: Boolean
    read_repo_hook: Boolean
    read_user: Boolean
    repo: Boolean
    repo_deployment: Boolean
    repo_status: Boolean
    write_org: Boolean
    write_public_key: Boolean
    write_repo_hook: Boolean
  }

  type ConnectionOptionsGoogleOAuth2 {
    scope: [String]!
    profile: Boolean
    client_id: String
    client_secret: String
    # TODO: verify this should be here. set_user_root_attributes: Boolean

    calendar: Boolean
    adsense_management: Boolean
    allowed_audiences: [String]
    analytics: Boolean
    blogger: Boolean
    chrome_web_store: Boolean

    contacts: Boolean
    content_api_for_shopping: Boolean
    coordinate: Boolean
    coordinate_readonly: Boolean
    document_list: Boolean
    email: Boolean
    gmail: Boolean
    google_affiliate_network: Boolean
    google_books: Boolean
    google_cloud_storage: Boolean
    google_drive: Boolean
    google_drive_files: Boolean
    google_plus: Boolean
    latitude_best: Boolean
    latitude_city: Boolean
    moderator: Boolean
    orkut: Boolean
    picasa_web: Boolean


    sites: Boolean
    spreadsheets: Boolean
    tasks: Boolean
    url_shortener: Boolean
    webmaster_tools: Boolean
    youtube: Boolean
  }

  type ConnectionOptionsLine {
    scope: [String]! # already in array from server
    profile: Boolean
    client_id: String # AKA channel id
    client_secret: String # AKA chanel Secret
    set_user_root_attributes: Boolean
    #additional Properties
    email: Boolean
  }

  type ConnectionOptionsLinkedIn {
    scope: [String]! # This was sent as an array of strings from server
    profile: Boolean
    client_id: String
    client_secret: String
    set_user_root_attributes: Boolean
    # additional properties
    basic_profile: Boolean
    email: Boolean
    strategy_version : Int
  }

  type ConnectionOptionsPayPal {
    scope: [String]! # this is an array of strings from server
    profile: Boolean
    client_id:String
    client_secret: String
    set_user_root_attributes: Boolean
    # additional properties
    address: Boolean
    email: Boolean
    phone: Boolean
  }

  type ConnectionOptionsPayPalSandbox {
    scope: [String]! # this is an array of strings from server
    profile: Boolean
    client_id:String
    client_secret: String
    set_user_root_attributes: Boolean
    # additional properties
    address: Boolean
    email: Boolean
    phone: Boolean
  }

  type ConnectionOptionsPlanningCenter {
    scope: [String]!
    profile: Boolean
    client_id: String
    client_secret: String
    set_user_root_attributes: Boolean
    # Additional Properties
    people: Boolean
    protocol: String
  }

  type ConnectionOptionsRenRen {
    profile: Boolean,
    client_id: String,
    client_secret:String,
    set_user_root_attributes: Boolean
  }

  type ConnectionOptionsSalesForce {
    scope: [String]!
    profile: Boolean
    client_id: String # AKA Consumer Key
    client_secret: String # AKA Consumer Secret
    set_user_root_attributes: Boolean
  }

  type ConnectionOptionsSalesForceSandbox {
    scope: [String]!
    profile: Boolean
    client_id: String # AKA Consumer Key
    client_secret: String # AKA Consumer Secret
    set_user_root_attributes: Boolean
  }

  type ConnectionOptionsSalesForceCommunity {
    scope: [String]!
    profile: Boolean
    client_id: String # AKA Consumer Key
    client_secret: String # AKA Consumer Secret
    set_user_root_attributes: Boolean
  }

  type ConnectionOptionsShopify {
    shop: String,
    scope: [String]! # csv from server 
    client_id: String
    read_orders: Boolean
    read_themes: Boolean
    read_content: Boolean
    write_orders: Boolean
    write_themes: Boolean
    client_secret: String
    read_products: Boolean
    read_shipping: Boolean
    write_content: Boolean
    read_customers: Boolean
    write_products: Boolean
    write_shipping: Boolean
    write_customers: Boolean
    read_script_tags: Boolean
    read_fulfillments: Boolean
    write_script_tags: Boolean
    write_fulfillments: Boolean
    set_user_root_attributes: Boolean
  }

  type ConnectionOptionsThirtySevenSignals {
    # AKA Base Camp
    profile: Boolean
    client_id: String
    client_secret: String
    set_user_root_attributes: Boolean

  }

  type ConnectionOptionsTwitter {
    client_id: String
    client_secret: String
    profile: Boolean
    set_user_root_attributes: Boolean
  }

  type ConnectionOptionsVKontakte {
    scope: [String]! # comes as array from server
    profile: Boolean
    client_id: String
    client_secret: String
    set_user_root_attributes: Boolean
    # Additional Properties
    friends: Boolean
    notes: Boolean
    pages: Boolean
    photos: Boolean
    video: Boolean
    wall: Boolean
  }

  type ConnectionOptionsYahoo {
    scope: [String]!
    profile: Boolean
    client_id: String
    client_secret: String
    set_user_root_attributes: Boolean
    # Additional Atributes
    basic_profile: Boolean
    basic_profile_write: Boolean
    email: Boolean
    extended_profile: Boolean
    extended_profile_write: Boolean
  }

  type ConnectionOptionsYandex {
    profile: Boolean
    client_id: String
    client_secret: String
    set_user_root_attributes: Boolean
  }

  type ConnectionOptionsYammer {
    profile: Boolean
    client_id: String
    client_secret: String
    set_user_root_attributes: Boolean
  }

  type ConnectionOptionsWeibo {
    user: Boolean
    email: Boolean
    scope: [String]! # comma seperated string from server
    tokenURL: URL
    client_id: String
    client_secret: String
    authorizationURL: URL
    invitation_write: Boolean
    direct_messages_read: Boolean
    direct_messages_write: Boolean
    friendships_groups_read: Boolean
    friendships_groups_write: Boolean
    set_user_root_attributes: Boolean
  }

  type ConnectionOptionsWordPress {
    scope: [String]!
    profile: Boolean
    client_id: String
    client_secret: String
    set_user_root_attributes: Boolean
  }
  
  # ------------------
  # Enterprise Connections
  # ------------------
  type ConnectionOptionsAuth0  {
    brute_force_protection: Boolean
    # configuration : ???? todo
    disable_signup : Boolean
    enable_database_customization : Boolean #verify this is a property
    import_mode : Boolean
    mfa : ConnectionOptionsAuth0MFA
    password_policy : StrengthLevel
    password_complexity_options : ConnectionOptionsAuth0PasswordComplexityOptions
    password_dictionary : ConnectionOptionsAuth0PasswordDictionary
    password_history : ConnectionOptionsAuth0PasswordHistory
    password_no_personal_info : ConnectionOptionsAuth0PasswordNoPersonalInfo
    requires_username : Boolean
    custom_scripts : String
    validation : ConnectionOptionsAuth0ValidationOptions
  }

  type ConnectionOptionsAuth0PasswordComplexityOptions {
    min_length : Int
  }

  type ConnectionOptionsAuth0PasswordDictionary {
    enable : Boolean
    dictionary : [String]!
  }

  type ConnectionOptionsAuth0PasswordHistory {
    enable : Boolean
    size : Int
  }

  type ConnectionOptionsAuth0PasswordNoPersonalInfo {
    enable : Boolean
  }
  

  type ConnectionOptionsAuth0MFA {
    active: Boolean
    return_enroll_settings : Boolean
  }

  type ConnectionOptionsAuth0ValidationOptions {
    username : ConnectionOptionsAuth0ValidationOptionsUserName
  }

  type  ConnectionOptionsAuth0ValidationOptionsUserName {
    min: Int
    max: Int
  }

  type ConnectionOptionsOIDC {
    scope :  [String]! # this was a space seperated list of strings
    # TODO is there a profile
    client_id: String
    # TODO is there a client secret?

    #Additional Properties
    authorization_endpoint : URL
    discovery_url : URL
    icon_url: URL
    issuer: String
    jwks_uri: URL
    set_user_root_attributes: Boolean
    token_endpoint: URL
    type: String
    userinfo_endpoint :  URL

  }

  type ConnectionOptionsSaml {
    cert : String
    debug : Boolean
    digestAlgorithm : String
    domain_aliases : [String]
    expires : String
    idpinitiated : ConnectionOptionsSamlIdpInitiated
    protocolBinding : String
    set_user_root_attributes: Boolean
    signatureAlgorithm : ConnectionOptionsSamlSignatureAlgorithm
    signatureDigest : ConnectionOptionsSamlSignatureAlgorithmDigest
    signingCert : String
    signInEndpoint : URL
    signOutEndpoint : URL
    # TODO fieldsMap, fieldsMapJsonRaw
    #fieldsMap : Object (Pair?) # (Optional) SAML Attributes mapping. If you're configuring a SAML enterprise connection for a non#standard PingFederate Server, you must update the attribute mappings.
    #fieldsMapJsonRaw :String
    signSAMLRequest : Boolean
    subject : ConnectionOptionsSamlSubject
    request_template : String
    tenant_domain : String
    thumbprints : [String]!
    user_id_attribute : String
  }

  type ConnectionOptionsSamlSubject {
    commonName : String
  }

  type ConnectionOptionsSamlIdpInitiated {
    client_id : String
    client_protocol : String
    client_authorizequery : String
    enabled : Boolean
  }

  type ConnectionOptionsWindowsLive {
    scope:  [String]
    client_id: String
    client_secret: String
    # TODO are we missing   set_user_root_attributes: Boolean

    strategy_version: Int
    graph_user_update: Boolean
    graph_device: Boolean
    graph_emails: Boolean
    graph_calendars: Boolean
    graph_contacts: Boolean
    graph_files: Boolean
    graph_files_update: Boolean
    graph_notes: Boolean
    graph_tasks_update: Boolean
    graph_notes_update: Boolean
    offline_access: Boolean
    graph_user_activity: Boolean
    graph_device_command: Boolean
    graph_emails_update: Boolean
    graph_calendars_update: Boolean
    graph_contacts_update: Boolean
    graph_files_all: Boolean
    graph_files_all_update: Boolean
    graph_notes_create: Boolean
    graph_tasks: Boolean
    graph_user: Boolean
    signin: Boolean

  }

  type ConnectionOptionsWAAD {
    client_id : String
    client_secret : String
    app_id : String  # TODO verify this is a property of WAAD Options
    app_domain : String
    api_enable_users : Boolean
    basic_profile: Boolean
    domain_aliases : [String]
    ext_profile : Boolean
    ext_groups : Boolean
    max_groups_to_retrieve : Int  # TODO verify this is a property of waad connection
    set_user_root_attributes: Boolean
    should_trust_email_verified_connection : String #todo possible enum?
    tenant_domain : String
    thumbprints : [String]
    use_wfed : Boolean # TODO verify this is a property of WAAD Options
    waad_protocol : String
    waad_common_endpoint : String # TODO URL? # verify this is a property of WAAD Options
  }


  # TODO: Consider Interfaces for 'types' of Connnections ? 
  #    interface SocialConnectionOptions {
  #        scope: [String]! # comes as array from server
  #        profile: Boolean
  #        client_id: String
  #        client_secret: String
  #        set_user_root_attributes: Boolean
  #    }
  #    
  #    interface EnterpriseConnectionOptions {
  #      client_id : String
  #      client_secret : String
  #    }


  type DeviceCredential {
    id : ID!
    client_id: String
    device_id : String
    device_name : String
    type : DeviceCredentialType
    user_id : String
  }

  type Grant {
    id : ID!
    audience : String
    clientID : String
    scope: [String]!
    user_id : String
  }


  type Hook {
    id: ID!
    triggerId: HookTriggerIdType!
    name: String!
    enabled: Boolean,
    script: String
    dependencies: JSON
  }

  type HookSecrets {
    id: ID!
    secrets: Pair
  }

  interface LogStream {
    id: ID!
    name: String!
    type: LogStreamType!
    status: LogStreamStatusType!
  }

  type LogStreamDataDog implements LogStream{
    id: ID!
    name: String!
    type: LogStreamType!
    status: LogStreamStatusType!
    # sink data
    datadogRegion: LogStreamDataDogRegion!
    datadogApiKey: String # e.g. aGkgbW9tCg
  }

  type LogStreamEventBridge implements LogStream {
    id: ID!
    name: String!
    type: LogStreamType!
    status: LogStreamStatusType!
    # sink data
    awsAccountId: String!,
    awsRegion: String!,
    awsPartnerEventSource: String!  # Auto generated at create time
  }
  type LogStreamEventGrid implements LogStream{
    id: ID!
    name: String!
    type: LogStreamType!
    status: LogStreamStatusType!
    # sink data
    azureSubscriptionId: String,
    azureResourceGroup: String,
    azureRegion: String,
    azurePartnerTopic: String
  }
  
  type LogStreamSplunk implements LogStream{
    id: ID!
    name: String!
    type: LogStreamType!
    status: LogStreamStatusType!
    # sink data
    splunkDomain: String, # Domain e.g. prd.mysplunk.splunkcloud.com
    splunkToken: String,  # GUID ex: c3348c69-29f4-4c09-bad5-708c3d095f4a
    splunkPort: Int,      # 8088
    splunkSecure: Boolean # this is verify TLS toggle. 
  }

  type LogStreamSumo implements LogStream{
    id: ID!
    name: String!
    type: LogStreamType!
    status: LogStreamStatusType!
    # sink data
    sumoSourceAddress: URL
  }

  type LogStreamWebhook implements LogStream {
    id: ID!
    name: String!
    type: LogStreamType!
    status: LogStreamStatusType!
    # sink data
    httpContentFormat: LogStreamWebhookContentFormat,
    httpContentType: String,
    httpEndpoint: URL,
    httpAuthorization: String
  }
  
  type OutputApiDelete {
    id: ID
  }
  type OutputClientDelete {
    client_id: ID!
  }

  type OutputClientGrantDelete {
    id: ID!
  }

  type OutputConnectionDelete {
    id : ID!
  }

  type OutputConnectionUserDelete {
    id: ID!
    email: String
  }

  type OutputDeviceCredentialDelete {
    id: ID!
  }

  type OututLogStreamDeleted {
    id: ID!
  }

  type OutputGrantDelete {
    id : String
    user_id : String
  }

  type OutputRoleDelete{
    id: ID!
  }
  

  # TODO :   NativeSocialLogins  
  #    "native_social_login": {
  #    "apple": {
  #    "enabled": false
  #    },
  #    "facebook": {
  #    "enabled": false
  #    }
  #    },



  type PageBackgroundColor {
    color: HCC
  }

  type PageBackgroundGradient  {
    type: String   # ex. 'linear-gradient', 
    start:  HCC    # '#FFFFFF',
    end: HCC     # '#000000'
    angle_deg: Int # 35
  }
  
  type Prompt {
      universal_login_experience: String!
  }

  type Api {
    id: ID!
    name: String!
    identifier: String!
    signing_alg: ApiSigningAlgorythmType!
    
    allow_offline_access: Boolean
    client: JSON       # not sure what this is.
    enforce_policies: Boolean
    is_system: Boolean! # Read Only
    scopes: [ApiScope]!
    signing_secret: String
    skip_consent_for_verifiable_first_party_clients: Boolean
    token_dialect:  TokenDialectType
    token_lifetime: Int
    token_lifetime_for_web: Int
  }

  type ApiScope {
    description: String
    value: String!
  }
  
  type Role{
    id: String,
    name: String,
    description: String
  }

  type RolePermission{
    resource_server_identifier: ID!
    permission_name: String
    resource_server_name: String
    description: String
  }




  # ------------------
  # mutations 
  # ----------------
  type Mutation{
    apiCreate(input: ApiCreateInput): Api
    apiDelete(id:ID!): OutputApiDelete
    apiUpdate(input: ApiUpdateInput) : Api
    
    updateBranding( patches: BrandingUpdateInput): Branding
    updateBrandingTemplates ( patches: BrandingTemplatesUpdateInput): BrandingTemplates
    deleteBrandingTemplates : BrandingTemplates

    createClient(name: String!): Client
    updateClient(id: String!, patches: ClientUpdateInput): Client
    deleteClient(id: String!) :  OutputClientDelete
    rotateClient(id: String!) : Client

    createClientGrant(payload: ClientGrantCreateInput) : ClientGrant
    updateClientGrant(id: String!, payload: ClientGrantUpdateInput) : ClientGrant
    deleteClientGrant(id: String!) :  OutputClientGrantDelete

    createConnection(payload: ConnectionCreateInput) : Connection
    deleteConnection(id: String!) :  OutputConnectionDelete
    deleteConnectionUser(input: ConnectionUserDeleteInput): OutputConnectionUserDelete
    deleteDeviceCredential(id: String!) :  OutputDeviceCredentialDelete

    deleteGrant(input: GrantDeleteInput!) : OutputGrantDelete

    createHook(input: HookCreateInput!) : Hook
    # TODO think about a delete pattern where we first get the resource to delete, if not exist, then
    # return 204, if exists call delete and pass back object from first call, in this case a 'Hook'
    # instead of a OutPutGHookDelete.
    deleteHook(input: HookInput) : Hook
    updateHook(input: HookInput) : Hook

    addHookSecrets(input: HookSecretsAddInput) : HookSecrets
    updateHookSecrets(input: HookSecretsUpdateInput) : HookSecrets
    deleteHookSecrets(input: HookSecretsDeleteInput) : HookSecrets

    createLogStreamDataDog(input : LogStreamDataDogCreateInput) : LogStream
    createLogStreamEventBridge(input : LogStreamEventBridgeCreateInput) : LogStream
    createLogStreamEventGrid(input : LogStreamEventGridCreateInput) : LogStream
    createLogStreamSplunk(input : LogStreamSplunkCreateInput) : LogStream
    createLogStreamSumo(input : LogStreamSumoCreateInput) : LogStream
    createLogStreamWebhook(input : LogStreamWebhookCreateInput) : LogStream
    deleteLogStream(id:ID!) : OututLogStreamDeleted
    updateLogStreamDataDog(input : LogStreamDataDogUpdateInput) : LogStream
    updateLogStreamEventBridge(input : LogStreamEventBridgeUpdateInput) : LogStream
    updateLogStreamEventGrid(input : LogStreamEventGridUpdateInput) : LogStream
    updateLogStreamSplunk(input : LogStreamSplunkUpdateInput) : LogStream
    updateLogStreamSumo(input : LogStreamSumoUpdateInput) : LogStream
    updateLogStreamWebhook(input : LogStreamWebhookUpdateInput) : LogStream

    roleCreate(input: RoleCreateInput): Role
    roleDelete(input: RoleDeleteInput): OutputRoleDelete
    roleUpdate(input: RoleUpdateInput) : Role
  }

  # ------------------
  # querys
  # ------------------
  type Query {
    apiById(id: ID!) : Api!
    apis: [Api]!
    apisByFilter(input: ApiByFilterInput) : [Api]!
    
    branding: Branding
    brandingTemplates: BrandingTemplates
    
    client(id: ID!) : Client
    clientGrants: [ClientGrant]!
    clientGrantsByFilter( filter : ClientGrantsByFilterInput): [ClientGrant]!
    clients: [Client]!
    clientsByFilter(filter : ClientsByFilterInput): [Client]!
    clientsByName(name : String!) : [Client]!
    
    connection(id: ID!) : Connection
    connectionStatus(id: ID!) : ConnectionStatus
    connections: [Connection]!
    connectionsByFilter(filter: ConnectionByFilterInput): [Connection]!
    connectionsByName(name: String!) :[Connection]!
    connectionsByStrategy(strategy: ConnectionStrategy!) :[Connection]!
    
    deviceCredentialsByFilter(filter: DeviceCredentialsByFilterInput!) : [DeviceCredential]!
    
    grants: [Grant]!
    grantsByFilter : [Grant!]
    
    hook(input: HookInput) : Hook
    hookSecrets(id:ID): HookSecrets! # TODO better way? PAIR? HASHMAP?
    hooks: [Hook]!
    hooksByFilter(filter : HooksByFilterInput): [Hook]!
    
    logStream(id:ID): LogStream
    logStreams: [LogStream]!

    roleById(id: ID!) :Role!
    roles: [Role]!
    rolesByFilter(input: RoleByFilterInput) : [Role]!
    
    #rolePermissionsByFilter(Input Role)
  }
  

  # ------------------
  # scalars
  # ------------------
  scalar HCC
  scalar JSON
  scalar JSONObject # Use for those items we cannot yet define or can't define
  scalar Pair
  scalar URL


  # ------------------
  # unions
  # ------------------
  union BrandingPageBackground = PageBackgroundGradient | PageBackgroundColor
  union ConnectionOptions = ConnectionOptionsApple # Social
    #| ConnectionOptions1KosmosBlockId      # Social - TODO requires non-gmail address to create account.
    | ConnectionOptionsAmazon              # Social
    | ConnectionOptionsAuth0
    | ConnectionOptionsBaidu               # Social
    | ConnectionOptionsBitBucket           # Social
    | ConnectionOptionsBox                 # Social
    | ConnectionOptionsDAccount            # Social
    | ConnectionOptionsDWolla              # Social
    | ConnectionOptionsDropBox             # Social
    | ConnectionOptionsEvernote            # Social
    | ConnectionOptionsEvernoteSandbox     # Social
    | ConnectionOptionsExact               # Social
    | ConnectionOptionsFacebook            # Social
    | ConnectionOptionsFitBit              # Social
    | ConnectionOptionsGitHub              # Social
    | ConnectionOptionsGoogleOAuth2
    | ConnectionOptionsLine                # Social
    | ConnectionOptionsLinkedIn            # Social
    | ConnectionOptionsOIDC                # enterprise
    | ConnectionOptionsOAuth2              # Social (digitalocean, discord, dribbble, figma, imgur, kakao, twitch,slack, stripe, spotify, quickbooks )
    | ConnectionOptionsPayPal              # Social
    | ConnectionOptionsPayPalSandbox       # Social
    | ConnectionOptionsPlanningCenter      # Social
    | ConnectionOptionsRenRen              # Social
    | ConnectionOptionsSalesForce          # Social
    | ConnectionOptionsSalesForceCommunity # Social
    | ConnectionOptionsSalesForceSandbox   # Social
    | ConnectionOptionsSaml                # enterprise
    | ConnectionOptionsShopify             # Social
    | ConnectionOptionsThirtySevenSignals  # Social - baseCamp?
    | ConnectionOptionsTwitter             # Social
    | ConnectionOptionsVKontakte           # Social
    | ConnectionOptionsWAAD                # enterprise
    | ConnectionOptionsWeibo               # Social
    | ConnectionOptionsWindowsLive         # Social
    | ConnectionOptionsWordPress           # Social
    | ConnectionOptionsYahoo               # Social
    | ConnectionOptionsYammer              # Social
    | ConnectionOptionsYandex              # Social


`

module.exports = { typeDefs }
