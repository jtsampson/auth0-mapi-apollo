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

    enum AppType {
        MACHINE_TO_MACHINE # non_interactive
        NATIVE # native
        REGULAR_WEB # regular_web
        SINGLE_PAGE # spa
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

    enum TokenEndpointAuthMethod {
        NONE
        POST
        BASIC
    }

    enum ConnectionOptionsSamlSignatureAlgorithm {
        RSA_SHA1
        RSA_SHA256
    }
    enum ConnectionOptionsSamlSignatureAlgorithmDigest {
        SHA1
        SHA256
    }

    # ------------------
    # inputs 
    # ------------------
    input InputBrandingUpdate {
        colors: InputBrandingColorsUpdate
        favicon_url : URL
        font : InputBrandingFontUpdate
        logo_url: URL
       # templates: InputBrandingTemplatesUpdate
    }
    
    input InputBrandingTemplatesUpdate {
        universal_login : String
    }

    input InputBrandingColorsUpdate {
        primary : HCC
        # todo error if both, rewrite in update to use page_background
        page_background_as_string : HCC
        page_background_as_gradient :InputBrandingPageBackgroundGradientUpdate
    }

    input InputBrandingPageBackgroundGradientUpdate  {
        type: String
        start:  HCC
        end: HCC
        angle_deg: Int
    }

    input InputBrandingFontUpdate {
        url : URL
    }


    input InputClientsByFilter {
        app_type : [AppType] # Note: this rest api expects comma seperated list of values.
        is_first_party : Boolean
        is_global : Boolean
        page : Int
        per_page : Int
    }

    input InputClientGrantsByFilter {
        audience : String
        client_id : ID
        page : Int
        per_page : Int
    }

    input InputConnectionByFilter {
        name : String
        strategy : ConnectionStrategy
        page : Int
        per_page : Int
    }
    
    input InputDeviceCredentialsByFilter {
        user_id: String!
        client_id: String
        type: String
        page : Int
        per_page : Int
    }

    input InputGrantsByFilter {
        user_id : String
        client_id : String
        audience : String
        page : Int
        per_page : Int
    }

    input InputGrantDelete {
        id : String
        user_id : String
    }

    input InputHooksByFilter {
        triggerID : String
        enabled :Boolean
        page : Int
        per_page : Int
    }

    input InputClientDelete {
        client_id : String
    }

    input InputClientGrantCreate {
        audience : String
        client_id : ID
        scope: [String]
    }

    input InputConnectionCreate {
        name: String!
        strategy: ConnectionStrategy!
    }

    input InputConnectionUserDelete {
       id: ID!
        email: String
    }

    input InputHookCreate {
        name: String
        enabled: Boolean
        script: String
        dependencies: JSON
    }

    input InputClientUpdate {
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
        jwt_configuration   : InputClientJWTConfigurationUpdate
        name: String
        oidc_conformant: Boolean
        sso_disabled: Boolean
    }

    input InputClientGrantUpdate {
        audience : String
        client_id : ID
        scope: String
    }

    input InputClientJWTConfigurationUpdate  {
        lifetime_in_seconds: Int
        secret_encoded: Boolean!

    }

    input InputUpdateSigningKeysUpdate {
        cert: String
        pkcs7: String
        subject: String
    }

    # ------------------
    # types 
    # ------------------
    type AndroidClient {
        app_package_name: String
        sha256_cert_fingerprints : [String]
    }

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
    },

    type Client {
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
        encryption_key : EncryptionKeyClient
        form_template : String
        global: Boolean!
        grant_types: [GrantType]!
        initiate_login_uri : String
        is_first_party: Boolean!
        is_token_endpoint_ip_header_trusted: Boolean
        jwt_configuration   : JWTConfigurationClient
        logo_uri : URL
        mobile : MobileClient
        name: String!
        # native_social_Logins # TODO 
        oidc_conformant: Boolean!
        refresh_token : RefreshTokenClient
        signing_keys: SigningKeysClient
        sso: Boolean
        sso_disabled: Boolean
        tenant: String!
        token_endpoint_auth_method : TokenEndpointAuthMethod
        web_origins : [String]

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
        # TODO does this have 'profile:'? could default to false.
        client_id:String
        app_secret: String # TODO could this be renamed to client_secret?
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
        # TODO scope:  not here, but could be added an always empty.
        profile: Boolean
        client_id: String
        client_secret: String
        set_user_root_attributes: Boolean
      
    }
    
    type ConnectionOptionsBox {
        # TODO scope:  not here, but could be added an always empty.
        profile: Boolean
        client_id: String
        client_secret: String
        set_user_root_attributes: Boolean
    }

    type ConnectionOptionsDAccount {
        # TODO scope:  not here, but could be added an always empty.
        profile: Boolean
        client_id: String
        client_secret: String
        set_user_root_attributes: Boolean
    }
    
    type ConnectionOptionsOAuth2 {
        scope: [String]! # this is returned by api as a single string e,g, scope: "read" but we'll convert to array.
        # TODO does this have 'profile:'? could default to false.
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
        # TODO does this have 'profile:'? could default to false.
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
        # TODO scope:  not here, but could be added an always empty.
        profile: Boolean
        client_id: String
        client_secret: String
        set_user_root_attributes: Boolean
    }
    
    type ConnectionOptionsEvernote {
        # TODO scope:  not here, but could be added an always empty.
        profile: Boolean
        client_id: String
        client_secret: String
        set_user_root_attributes: Boolean
    }

    type ConnectionOptionsEvernoteSandbox {
        # TODO scope:  not here, but could be added an always empty.
        profile: Boolean
        client_id: String
        client_secret: String
        set_user_root_attributes: Boolean
    }

    type ConnectionOptionsExact {
        # TODO scope:  not here, but could be added an always empty.
        profile: Boolean
        client_id: String
        client_secret: String
        set_user_root_attributes: Boolean
        # additional properteis
        baseUrl: URL
        
    }

    type ConnectionOptionsFacebook {
        scope: [String]! # TODO  scope is stored as a csv string in auth0 
        # TODO does this have 'profile:'? could default to false.
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
        # TODO scope:  not here, but could be added an always empty.
        profile: Boolean
        client_id: String
        client_secret: String
        set_user_root_attributes: Boolean
        
    }

    type ConnectionOptionsTwitter {
        # TODO scope:  not here, but could be added an always empty.
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
        # TODO scope:  not here, but could be added an always empty.
        profile: Boolean
        client_id: String
        client_secret: String
        set_user_root_attributes: Boolean
    }
    
    type ConnectionOptionsYammer {
        # TODO scope:  not here, but could be added an always empty.
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
        mfa : MFA
        password_policy : StrengthLevel
        password_complexity_options : PasswordComplexityOptions
        password_dictionary : PasswordDictionary
        password_history : PasswordHistory
        password_no_personal_info : PasswordNoPersonalInfo
        requires_username : Boolean
        custom_scripts : String
        validation : ValidationOptions
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
        # TODO does this have 'profile:'? could default to false. is this social?
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
    
    input InputDeviceCredentialPublicKeyCreate

    
    type Hook {
        id: String,
        triggerId: String
        name: String
        enabled: Boolean,
        script: String
        dependencies: JSON
    }

    type ValidationOptions {
        username : UserNameValidationOptions
    }

    type MFA {
        active: Boolean
        return_enroll_settings : Boolean
    }

    type PasswordComplexityOptions {
        min_length : Int
    }

    type PasswordDictionary {
        enable : Boolean
        dictionary : [String]!
    }

    type PasswordHistory {
        enable : Boolean
        size : Int
    }

    type PasswordNoPersonalInfo {
        enable : Boolean
    }

    type  UserNameValidationOptions {
        min: Int
        max: Int
    }

    #    type EnterpriseConnectionOptions implements ConnectionOptions {
    #      name: String
    #      strategy : String
    #      basicProfile: Boolean
    #      ext_profile : Boolean
    #      ext_admin : Boolean
    #      ext_is_suspended : Boolean
    #      ext_agreed_terms : Boolean 
    #      ext_groups : Boolean
    #      ext_assigned_plans : Boolean
    #      api_enable_users : Boolean
    #      #api_enable_users # todo
    #      #requires_username
    #    }


    type OutputClientDelete {
        client_id: ID!
    }

    type DeleteClientGrantPayload {
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

    type DeleteGrantPayload {
        triggerID : String
        user_id : String
    }

    type Enabled {
        enabled : Boolean
    }

    type EncryptionKeyClient {
        pub: String
        cert: String
        subject:String
    }

    type JWTConfigurationClient  {
        lifetime_in_seconds: Int
        secret_encoded: Boolean!
        #TODO add scopes?
        #scopes: {}, 
        alg:String # TODO could be ENUM 'HS256' or 'RS256'
    }

    type IOSClient {
        team_id: String
        app_bundle_identifier :String
    }

    type MobileClient {
        android : AndroidClient
        ios : IOSClient
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

    type RefreshTokenClient {
        expiration_type: ExpirationType
        idle_token_lifetime : Int
        infinite_idle_token_lifetime: Boolean
        infinite_token_lifetime: Int
        leeway: Int
        rotation_type: RotationType
        token_lifetime: Int
    },

    type SigningKeysClient {
        cert: String
        pkcs7: String
        subject: String
    }

    type Grant {
        id : ID!
        audience : String
        clientID : String
        scope: [String]!
        user_id : String
    }

    # ------------------
    # mutations 
    # ----------------
    # TODO: consider this direction https://stackoverflow.com/questions/44120314/result-of-a-delete-mutation 
    # TODO: related to seperate input and output types
    # TODO: consider adding 'id' to 'payload' for sake of api for updates.
    type Mutation{
        updateBranding( patches: InputBrandingUpdate): Branding
        updateBrandingTemplates ( patches: InputBrandingTemplatesUpdate): BrandingTemplates
        deleteBrandingTemplates : BrandingTemplates

        createClient(name: String!): Client
        updateClient(id: String!, patches: InputClientUpdate): Client
        deleteClient(id: String!) :  OutputClientDelete
        rotateClient(id: String!) : Client

        createClientGrant(payload: InputClientGrantCreate) : ClientGrant
        updateClientGrant(id: String!, payload: InputClientGrantUpdate) : ClientGrant
        deleteClientGrant(id: String!) :  DeleteClientGrantPayload

        createConnection(payload: InputConnectionCreate) : Connection
        deleteConnection(id: String!) :  OutputConnectionDelete
        deleteConnectionUser(input: InputConnectionUserDelete): OutputConnectionUserDelete
        deleteDeviceCredential(id: String!) :  OutputDeviceCredentialDelete

        deleteGrant(input: InputGrantDelete!) : OutputGrantDelete

        createHook(input: InputHookCreate!) : Hook
    }

    # ------------------
    # querys
    # ------------------
    type Query {
        branding: Branding
        brandingTemplates: BrandingTemplates

        client(id: ID!) : Client
        clients: [Client]!
        clientsByFilter(filter : InputClientsByFilter): [Client]!
        clientsByName(name : String!) : [Client]!

        clientGrants: [ClientGrant]!
        clientGrantsByFilter( filter : InputClientGrantsByFilter): [ClientGrant]!

        connections: [Connection]!
        connectionsByFilter(filter: InputConnectionByFilter): [Connection]!
        connectionsByName(name: String!) :[Connection]!
        connectionsByStrategy(strategy: ConnectionStrategy!) :[Connection]!
        connection(id: ID!) : Connection
        connectionStatus(id: ID!) : ConnectionStatus

        deviceCredentialsByFilter(filter: InputDeviceCredentialsByFilter!) : [DeviceCredential]!

        grants: [Grant]!
        grantsByFilter : [Grant!]

        hooks: [Hook]!
        hooksByFilter(filter : InputHooksByFilter): [Hook]!
    }

    type OutputGrantDelete {
        id : String
        user_id : String
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
