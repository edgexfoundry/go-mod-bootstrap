
<a name="Bootstrap Go Mod Changelog"></a>
## Bootstrap Module (in Go)
[Github repository](https://github.com/edgexfoundry/go-mod-bootstrap)

## Change Logs for EdgeX Dependencies

- [go-mod-core-contracts](https://github.com/edgexfoundry/go-mod-core-contracts/blob/main/CHANGELOG.md)
- [go-mod-messaging](https://github.com/edgexfoundry/go-mod-messaging/blob/main/CHANGELOG.md)
- [go-mod-registry](https://github.com/edgexfoundry/go-mod-registry/blob/main/CHANGELOG.md)
- [go-mod-secrets](https://github.com/edgexfoundry/go-mod-secrets/blob/main/CHANGELOG.md)
- [go-mod-configuration](https://github.com/edgexfoundry/go-mod-configuration/blob/main/CHANGELOG.md) 

## [v4.0.0] - 2025-03-12

### Features ✨

- Use go-mod-messaging updated `NewMessageEnvelope` functions ([689d11e…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/689d11e68f960c6c14ce082c34596ae70a65391e))
- Pass a callback function to `WatchForChanges` method ([b6bb7df…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/b6bb7df54b72900fcda88764a7a262809c7ef0bc))
- Enhance the authentication hook function to support external JWT ([7262530…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/72625307fddf58a71365790e5e0be9b42f7a78ae))
- Remove unused DeviceServiceCallbackClient ([7b366ed…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/7b366ed6b72269b97670537de5a767f6419a1c50))
- Add new go build tag no_openziti to reduce build size ([#795](https://github.com/edgexfoundry/go-mod-bootstrap/issues/795)) ([84aca22…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/84aca22400148320c57e09313d7449f5f8115793))
- Add EDGEX_USE_COMMON_APP_SERVICE_SECRET_KEY for service key overwrite ([f50d47c…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/f50d47cdb4fa0fe79d3d17d162436ddd25ceae0b))
- Remove consul dependency ([f96ab66…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/f96ab668d791aab77e23aaafed7abcc7644c67b4))
```text

BREAKING CHANGE: Remove consul dependency

```
- Add new env to support -o flag ([e434cfd…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/e434cfdce0460ca50b9e4eb39b13d3f67b6c892e))
- Add Core-Keeper support ([080e5c8…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/080e5c897ab1dda4b94d78b7c372d6709be40d7f))
- Add service key to HTTP Server ([#679](https://github.com/edgexfoundry/go-mod-bootstrap/issues/679)) ([29e6be3…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/29e6be3fc9be9fbd702a2e04303cff05dbc064c4))
- Allow clients to be zero trust ([#678](https://github.com/edgexfoundry/go-mod-bootstrap/issues/678)) ([8d0240b…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/8d0240bc54551be018be9a3c56ae3a4d4077960c))
- Initial implemention of openziti to go-mod-bootstrap ([#659](https://github.com/edgexfoundry/go-mod-bootstrap/issues/659)) ([4121a9d…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/4121a9d94e80f18bcd1a00453943416b0e7bee92))


### ♻ Code Refactoring 

- Update go module to v4 ([6033f3b…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/6033f3b516f7a5c480af45f64e54ef7bf3ebd196))

### 🐛 Bug Fixes

- Obtain the updated configuration provider client to handle configuration changes ([a102aaa…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/a102aaa88e6157ae4f10e700649ce459678db03b))
- Add the security-proxy-auth svc client ([8b40366…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/8b40366ef811c77a489073e1d2e5798a88ef11f7))
- Call the next handler function in the auth_middleware ([f48dd5b…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/f48dd5bce7e6d8322f74a8837d508bc8a732ffc9))
- Define SecretStoreAuth in the separate file ([46f501e…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/46f501e4dcabb1ffe69c872c4c876d19e628ad96))
- Add the missing import in auth_middleware_no_ziti ([d68de5a…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/d68de5a9a2dcd206b405c97d306b965e2ac4107f))
- Remove unit tests related to redis pub/sub ([#793](https://github.com/edgexfoundry/go-mod-bootstrap/issues/793)) ([1eae02d…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/1eae02d0b1549b634448567cd0d7a360a0398db7))
```text

BREAKING CHANGE: Remove redis pub/sub

```
- The env should override flags ([fe8b0f6…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/fe8b0f6cacb45d2182d28f4c6e9322bd5df5cb90))


### 👷 Build

- Upgrade to go-1.23, Linter1.61.0 ([3a67eaa…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/3a67eaaa63d9f35c3d54c0ad5787606cacd7d90e))


## [v3.1.0] - 2023-11-15

### ✨  Features

- Add EnableNameFieldEscape config ([b63a581…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/b63a5810faa868c4fedd8bb64209569178cd803b))
- Add new -rsh/--remoteServiceHosts flag and corresponding env override ([#596](https://github.com/edgexfoundry/go-mod-bootstrap/issues/596)) ([1d77273…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/1d77273f7ae052ea4eae83196136ad2264b0ca56))
- Add wrapper func to wrap http handler for Echo ([e1ab269…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/e1ab26919fdbaaa713e5edea933bdefb6ec92739))
- Move the common middleware to go-mod-bootstrap ([#567](https://github.com/edgexfoundry/go-mod-bootstrap/issues/567)) ([8addaa2…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/8addaa2ea19495c6dfa41c603405950b1e572c4f))
- Replace gorilla/mux router with echo ([#557](https://github.com/edgexfoundry/go-mod-bootstrap/issues/557)) ([d7c12cc…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/d7c12cc22d3e7aeafa8ef131c4e1bcef5e7d6f44))
- Add better error handling when common config is missing ([#566](https://github.com/edgexfoundry/go-mod-bootstrap/issues/566)) ([dcdd37f…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/dcdd37f02bb774d2396efd74975d9f1fe0813359))
- Move all the common APIs into go-mod-bootstrap ([#562](https://github.com/edgexfoundry/go-mod-bootstrap/issues/562)) ([40eb783…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/40eb783d62ac8c1fbdb1eb22585f3ac60bc9a84b))
- Use loadfile that allows reading from local file or uri ([#558](https://github.com/edgexfoundry/go-mod-bootstrap/issues/558)) ([b171584…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/b171584baabd50881bf72082494493a340744952))
- Implement reusable load file function ([#555](https://github.com/edgexfoundry/go-mod-bootstrap/issues/555)) ([d15a138…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/d15a1387ea8c6e29ed6cc19ffa412ce73f341b75))


### 🐛 Bug Fixes

- Expand DevMode flag to set values for external access ([#601](https://github.com/edgexfoundry/go-mod-bootstrap/issues/601)) ([db3759c…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/db3759c59d39e98bdf0ca83cc7aace05fd638c89))
- Rename SecretPath to SecretName ([#551](https://github.com/edgexfoundry/go-mod-bootstrap/issues/551)) ([2d38a8b…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/2d38a8b95e73454354ad735e1dd2bea47a8371ca))


### 👷 Build

- Upgrade to go 1.21 and linter 1.54.2 ([#599](https://github.com/edgexfoundry/go-mod-bootstrap/issues/599)) ([ff44a32…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/ff44a32d95b8337476342a35d1a5d777bc26cdf3))


### 🧪 Testing

- Add httpserver test for uri4files to check secret header ([#597](https://github.com/edgexfoundry/go-mod-bootstrap/issues/597)) ([4fcc5d1…](https://github.com/edgexfoundry/go-mod-bootstrap/commit/4fcc5d18e9c04bd2c618068180bee74c5352e294))

## [v3.0.0] - 2023-05-31

### Features ✨
- Add support for wildcard in secret updated callback and rename RegisteredSecretUpdatedCallback  ([#d335988](https://github.com/edgexfoundry/go-mod-bootstrap/commit/d3359882e7a0b8fc3808c94e27140267c7d8c1a0))
  ```text
  BREAKING CHANGE: Renamed RegisteredSecretUpdatedCallback to RegisterSecretUpdatedCallback
  ```
- Apply env overrides only when config loaded from file ([#99b3ee9](https://github.com/edgexfoundry/go-mod-bootstrap/commit/99b3ee95f87e24d2dc939cb57e681beebcc2188f))
  ```text
  BREAKING CHANGE: Overrides are no longer applied to values pulled from Configuration Provider. Configuration Provider is now the system of record for configuration, when used.
  ```
- Load common configuration ([#e74b4a8](https://github.com/edgexfoundry/go-mod-bootstrap/commit/e74b4a89c702c02832bb8216fdda8847bedc2ac3))
  ```text
  BREAKING CHANGE: calls to bootstrap.RunAndReturnWaitGroup must include the service type
  ```
- Rename environment variables for the sake of consistency ([#402](https://github.com/edgexfoundry/go-mod-bootstrap/issues/402)) ([#ff25685](https://github.com/edgexfoundry/go-mod-bootstrap/commits/ff25685))
  ```
  BREAKING CHANGE:
  - `EDGEX_CONFIGURTION_PROVIDER` is replaced by `EDGEX_CONFIG_PROVIDER`
  - `EDGEX_CONF_DIR` is replaced by `EDGEX_CONFIG_DIR`
  ```
- Support /api/v3/secret endpoint in non-secure mode ([#542](https://github.com/edgexfoundry/go-mod-bootstrap/issues/542)) ([#77722ae](https://github.com/edgexfoundry/go-mod-bootstrap/commits/77722ae))
- Add Metrics for getting secret token and getting secret  ([#8d6813b](https://github.com/edgexfoundry/go-mod-bootstrap/commits/8d6813b))
- Add -d/--dev common command-line flag to put service in Dev Mode ([#516](https://github.com/edgexfoundry/go-mod-bootstrap/issues/516)) ([#0c0b475](https://github.com/edgexfoundry/go-mod-bootstrap/commits/0c0b475))
- Add command line/environment flag for commonConfig ([#487](https://github.com/edgexfoundry/go-mod-bootstrap/issues/487)) ([#fed18d9](https://github.com/edgexfoundry/go-mod-bootstrap/commits/fed18d9))
- Implement watch for common config writable ([#456](https://github.com/edgexfoundry/go-mod-bootstrap/issues/456)) ([#f5fe044](https://github.com/edgexfoundry/go-mod-bootstrap/commits/f5fe044))
- Implement new IsRegistered API for MetricsManager ([#446](https://github.com/edgexfoundry/go-mod-bootstrap/issues/446)) ([#8ddd9e2](https://github.com/edgexfoundry/go-mod-bootstrap/commits/8ddd9e2))
- Add go-mod-bootstrap hooks for JWT generation and verification ([#a31da98](https://github.com/edgexfoundry/go-mod-bootstrap/commits/a31da98))
- Add go-mod-bootstrap hooks for JWT generation and verification ([#8d2d623](https://github.com/edgexfoundry/go-mod-bootstrap/commits/8d2d623))


### Bug Fixes 🐛

- Check nil pointer in `buildPaths()` ([#495](https://github.com/edgexfoundry/go-mod-bootstrap/issues/495)) ([#02bbd1b](https://github.com/edgexfoundry/go-mod-bootstrap/commits/02bbd1b))
- InsecureSecrets change detection ([#525](https://github.com/edgexfoundry/go-mod-bootstrap/issues/525)) ([#a09e027](https://github.com/edgexfoundry/go-mod-bootstrap/commits/a09e027))
- Don't attempt to wrap error to LoggingClient ([#3bc6273](https://github.com/edgexfoundry/go-mod-bootstrap/commits/3bc6273))
- **metrics:** do not use shared DefaultRegistry and fix wg.Done call ([#543](https://github.com/edgexfoundry/go-mod-bootstrap/issues/543)) ([#4aa258a](https://github.com/edgexfoundry/go-mod-bootstrap/commits/4aa258a))

### Code Refactoring ♻
- Rework SecretProvider interface so App/Device Services have limited API ([#d95cec14](https://github.com/edgexfoundry/go-mod-bootstrap/commit/d95cec14f58e3cd099609bcde1004459619ca645))
  ```text
  BREAKING CHANGE: Services that need full SecretProvider API now use SecretProviderExt. Extra APIs have been removed for App/Device Services.
  ```
- Change Database timeout to a duration string ([#0c6b57a](https://github.com/edgexfoundry/go-mod-bootstrap/commit/0c6b57a37e828911869d3f8fcd99d2372771f96c))
  ```text
  BREAKING CHANGE: Database Timeout type has changed from `int` to duration`string`. Update configuration appropriately.
  ```
- Rework to remove use of TOML package ([#4f2cfc7](https://github.com/edgexfoundry/go-mod-bootstrap/commit/4f2cfc7b2138f8cecea866b1db01387ccea9e17f))
  ```text
  BREAKING CHANGE: OverrideTomlValues changed to OverrideConfigMapValues and GetConfigLocation changed to GetConfigFileLocation
  ```
- Switch to loading configuation files as YAML ([#9d98d1e](https://github.com/edgexfoundry/go-mod-bootstrap/commit/9d98d1e0776d9318972cb8a0c851d1c9cce628cc))
  ```text
  BREAKING CHANGE: All configruation file must now be in YAML format. The default file name has changed to be configuration.yaml
  ```
- Remove unused AuthModeKey and SecretNameKey ([#91df2ca](https://github.com/edgexfoundry/go-mod-bootstrap/commit/91df2cab5fbaba815e995a6abf77c007eaf8ddcd))
  ```text
  BREAKING CHANGE: AuthModeKey and SecretNameKey public constants have been removed
  ```
- Refactor all usages of path to be secretName in APIs ([#7449463](https://github.com/edgexfoundry/go-mod-bootstrap/commit/744946316a829875f36ac6478fef32162c01b121))
  ```text
  BREAKING CHANGE: path parameter has been renamed to secretName in all APIs
  ```
- Replace topics from config with new constants ([#45461fa](https://github.com/edgexfoundry/go-mod-bootstrap/commit/45461fad361632d16a9d7c5ffe600ba7f8b7715b))
  ```text
  BREAKING CHANGE: Topics no longer in configuration
  ```
- Rework MessageBus configuration for all services to use consistently ([#3599fd1](https://github.com/edgexfoundry/go-mod-bootstrap/commit/3599fd1662e5f817d604f170f0af8865bbfd19f0))
  ```text
  BREAKING CHANGE: MessageQueue renamed to MessageBus and fields changed. See v3 Migration guide.
  ```
- Replace SecretStore service config with default values and overrides ([#4709c62](https://github.com/edgexfoundry/go-mod-bootstrap/commit/4709c6263787ef6556c1d7017b033b47cb029bd0))
  ```text
  BREAKING CHANGE: SecretStore config no longer in service configuration file. Changes must be done via use of environment variable overrides of default values

  ```
- Rename command line flags for the sake of consistency ([#010e84a](https://github.com/edgexfoundry/go-mod-bootstrap/commit/010e84a4f5c9fb5bad160c9a325d4b1cd0611808))
  ```text
  BREAKING CHANGE:
    - `-c/--confdir` to `-cd/--configDir`
    - `-f/--file` to `-cf/--configFile`
  ```
- Don't add version to Config Stem ([#6cf9e04](https://github.com/edgexfoundry/go-mod-bootstrap/commit/6cf9e040e289ca8ddff99a8dd7769029d70563ed))
  ```text
  BREAKING CHANGE: Service configuration location in Consul has changed
  ```
- Update module to v3 ([#608b320](https://github.com/edgexfoundry/go-mod-bootstrap/commit/608b3207a4485660e9bf4596eb36916c67f542cc))
  ```text
  BREAKING CHANGE: Import paths will need to change to v3
  ```
- Use updated config provider function for isCommonConfigReady ([#450](https://github.com/edgexfoundry/go-mod-bootstrap/issues/450)) ([#e72e993](https://github.com/edgexfoundry/go-mod-bootstrap/commits/e72e993))
- Move configuration location code to public helper function ([#422](https://github.com/edgexfoundry/go-mod-bootstrap/issues/422)) ([#7c7ee01](https://github.com/edgexfoundry/go-mod-bootstrap/commits/7c7ee01))
- Config processor createProviderClient from receiver to helper ([#421](https://github.com/edgexfoundry/go-mod-bootstrap/issues/421)) ([#a9675b9](https://github.com/edgexfoundry/go-mod-bootstrap/commits/a9675b9))
- Adjust to MessageBus config with single broker host info ([#407](https://github.com/edgexfoundry/go-mod-bootstrap/issues/407)) ([#cd249ec](https://github.com/edgexfoundry/go-mod-bootstrap/commits/cd249ec))

### Build 👷

- Update to Go 1.20 and linter v1.51.2 ([#470](https://github.com/edgexfoundry/go-mod-bootstrap/issues/470)) ([#86c0411](https://github.com/edgexfoundry/go-mod-bootstrap/commits/86c0411))

## [v2.3.0] - 2022-11-09

### Features ✨

- Add capability to use messaging based Command Client ([#384](https://github.com/edgexfoundry/go-mod-bootstrap/issues/384)) ([#9ad12a8](https://github.com/edgexfoundry/go-mod-bootstrap/commits/9ad12a8))
- Add Consul security metrics ([#383](https://github.com/edgexfoundry/go-mod-bootstrap/issues/383)) ([#a43e448](https://github.com/edgexfoundry/go-mod-bootstrap/commits/a43e448))
- Add service metrics for Secrets requested and stored ([#376](https://github.com/edgexfoundry/go-mod-bootstrap/issues/376)) ([#42c52e2](https://github.com/edgexfoundry/go-mod-bootstrap/commits/42c52e2))
- Added SecretUpdated  API ([#373](https://github.com/edgexfoundry/go-mod-bootstrap/issues/373)) ([#f58aa0b](https://github.com/edgexfoundry/go-mod-bootstrap/commits/f58aa0b))
- Redact logging of insecure secrets env override ([#367](https://github.com/edgexfoundry/go-mod-bootstrap/issues/367)) ([#9565883](https://github.com/edgexfoundry/go-mod-bootstrap/commits/9565883))
- Added HasSecret API ([#364](https://github.com/edgexfoundry/go-mod-bootstrap/issues/364)) ([#61f5503](https://github.com/edgexfoundry/go-mod-bootstrap/commits/61f5503))
- Add new 'Topics' field and external MQTT BootstrapHandler ([#365](https://github.com/edgexfoundry/go-mod-bootstrap/issues/365)) ([#6dab13b](https://github.com/edgexfoundry/go-mod-bootstrap/commits/6dab13b))
- Add common Messaging bootstrap handler ([#360](https://github.com/edgexfoundry/go-mod-bootstrap/issues/360)) ([#aaf2123](https://github.com/edgexfoundry/go-mod-bootstrap/commits/aaf2123))
- Add Histogram to supported metric types ([#346](https://github.com/edgexfoundry/go-mod-bootstrap/issues/346)) ([#57130b2](https://github.com/edgexfoundry/go-mod-bootstrap/commits/57130b2))
- Put CA cert into MessageBusInfo for all AuthModes ([#324](https://github.com/edgexfoundry/go-mod-bootstrap/issues/324)) ([#4dbfa01](https://github.com/edgexfoundry/go-mod-bootstrap/commits/4dbfa01))

### Bug Fixes 🐛

- Add capability to override config provider settings with "none" ([#381](https://github.com/edgexfoundry/go-mod-bootstrap/issues/381)) ([#3493ca4](https://github.com/edgexfoundry/go-mod-bootstrap/commits/3493ca4))
- Run WatchForChange in a new thread ([#362](https://github.com/edgexfoundry/go-mod-bootstrap/issues/362)) ([#9c98e1c](https://github.com/edgexfoundry/go-mod-bootstrap/commits/9c98e1c))
- Ensure exit with non-zero code when error occurs ([#358](https://github.com/edgexfoundry/go-mod-bootstrap/issues/358)) ([#816d4c9](https://github.com/edgexfoundry/go-mod-bootstrap/commits/816d4c9))

### Build 👷

- Upgrade to Go 1.18 ([#1361f04](https://github.com/edgexfoundry/go-mod-bootstrap/commit/1361f04))

## [v2.2.0] - 2022-05-11

### Features ✨

- Add RequestLimitMiddleware for Service.MaxRequestSize config ([#321](https://github.com/edgexfoundry/go-mod-bootstrap/issues/321)) ([#42b690d](https://github.com/edgexfoundry/go-mod-bootstrap/commits/42b690d))
- Implement service metrics bootstrap and common capability ([#313](https://github.com/edgexfoundry/go-mod-bootstrap/issues/313)) ([#8132711](https://github.com/edgexfoundry/go-mod-bootstrap/commits/8132711))
- Location of client service obtained from the registry ([#305](https://github.com/edgexfoundry/go-mod-bootstrap/issues/305)) ([#78c5fc9](https://github.com/edgexfoundry/go-mod-bootstrap/commits/78c5fc9))
- **security:** Use go-mod-secrets version that includes the capability of using non_delayedstart go build tags ([#317](https://github.com/edgexfoundry/go-mod-bootstrap/issues/317)) ([#2a6ac6a](https://github.com/edgexfoundry/go-mod-bootstrap/commits/2a6ac6a))
- **security:** Integrate runtime spiffe token provider client from go-mod-secrets ([#4bf6376](https://github.com/edgexfoundry/go-mod-bootstrap/commits/4bf6376))

### Bug Fixes 🐛

- Generate proper Consul basepath on Windows ([#0cfe34c](https://github.com/edgexfoundry/go-mod-bootstrap/commits/0cfe34c))
- **config:** ignore first change notification in ListenForCustomConfigChanges ([#315](https://github.com/edgexfoundry/go-mod-bootstrap/issues/315)) ([#6332299](https://github.com/edgexfoundry/go-mod-bootstrap/commits/6332299))

### Build 👷

- Added "make lint" target and added to "make test" target  ([#302](https://github.com/edgexfoundry/go-mod-bootstrap/issues/302)) ([#d813076](https://github.com/edgexfoundry/go-mod-bootstrap/commits/d813076))

<a name="v2.1.0"></a>
## [v2.1.0] - 2021-11-17

### Features ✨

- Use Http Request timeout handler ([#267](https://github.com/edgexfoundry/go-mod-bootstrap/issues/267)) ([#4da2238](https://github.com/edgexfoundry/go-mod-bootstrap/commits/4da2238))
- **security:** Add Access Token callback Vault token reload ([#285](https://github.com/edgexfoundry/go-mod-bootstrap/issues/285)) ([#64217dd](https://github.com/edgexfoundry/go-mod-bootstrap/commits/64217dd))
- **security:** Add optional capability to seed service secrets ([#276](https://github.com/edgexfoundry/go-mod-bootstrap/issues/276)) ([#a4676a4](https://github.com/edgexfoundry/go-mod-bootstrap/commits/a4676a4))
- **security:** Add func to process CORS ([#288](https://github.com/edgexfoundry/go-mod-bootstrap/issues/288)) ([#c292656](https://github.com/edgexfoundry/go-mod-bootstrap/commits/c292656))
- **security:** Create CORS related config struct ([#286](https://github.com/edgexfoundry/go-mod-bootstrap/issues/286)) ([#4ec4738](https://github.com/edgexfoundry/go-mod-bootstrap/commits/4ec4738))

### Bug Fixes 🐛

- Use correct name when logging EDGEX_CONF_DIR override ([#266](https://github.com/edgexfoundry/go-mod-bootstrap/issues/266)) ([#2a375e7](https://github.com/edgexfoundry/go-mod-bootstrap/commits/2a375e7))

## [v2.0.0] - 2021-06-30
### Features ✨
- **v2:** Add Subscribe config to MessageQueue config ([#240](https://github.com/edgexfoundry/go-mod-bootstrap/issues/240)) ([#ac14ba0](https://github.com/edgexfoundry/go-mod-bootstrap/commits/ac14ba0))
- **v2:** Add bootstrap handler to create Messaging Client with secure options ([#225](https://github.com/edgexfoundry/go-mod-bootstrap/issues/225)) ([#ae196fc](https://github.com/edgexfoundry/go-mod-bootstrap/commits/ae196fc))
- **v2:** Use SecretProvider to get Config/Registry access tokens ([#202](https://github.com/edgexfoundry/go-mod-bootstrap/issues/202)) ([#5d19aa5](https://github.com/edgexfoundry/go-mod-bootstrap/commits/5d19aa5))
- **v2:** Enable use of Registry & Config client access token ([#195](https://github.com/edgexfoundry/go-mod-bootstrap/issues/195)) ([#f9d06ec](https://github.com/edgexfoundry/go-mod-bootstrap/commits/f9d06ec))
- **v2:** Add overwrite capability for custom configuration ([#185](https://github.com/edgexfoundry/go-mod-bootstrap/issues/185)) ([#90b8a51](https://github.com/edgexfoundry/go-mod-bootstrap/commits/90b8a51))
- **v2:** Add support for load/listen custom configuration ([#180](https://github.com/edgexfoundry/go-mod-bootstrap/issues/180)) ([#f277873](https://github.com/edgexfoundry/go-mod-bootstrap/commits/f277873))
- **v2:** Add config client in DIC ([#178](https://github.com/edgexfoundry/go-mod-bootstrap/issues/178)) ([#ecde49d](https://github.com/edgexfoundry/go-mod-bootstrap/commits/ecde49d))
- **v2:** Add helper to query DIC and returns the DeviceServiceCommandClient instance ([#162](https://github.com/edgexfoundry/go-mod-bootstrap/issues/162)) ([#c087e44](https://github.com/edgexfoundry/go-mod-bootstrap/commits/c087e44))
- **v2:** Create Helper functions to retrieve client library instances through DIC ([#158](https://github.com/edgexfoundry/go-mod-bootstrap/issues/158)) ([#3d89601](https://github.com/edgexfoundry/go-mod-bootstrap/commits/3d89601))
### Bug Fixes 🐛
- Use /api/v2/ping for Registry healthchecks ([#196](https://github.com/edgexfoundry/go-mod-bootstrap/issues/196)) ([#7d55b1a](https://github.com/edgexfoundry/go-mod-bootstrap/commits/7d55b1a))
- Add conditional for error message and return false on error ([#f4390fe](https://github.com/edgexfoundry/go-mod-bootstrap/commits/f4390fe))
- Replace hyphen with underscore in override names ([#216](https://github.com/edgexfoundry/go-mod-bootstrap/issues/216)) ([#9f3edfd](https://github.com/edgexfoundry/go-mod-bootstrap/commits/9f3edfd))
    ```
    BREAKING CHANGE:
    Overrides that have hyphens will not longer work and must be updated replace hyphens with underscores.
    ```
- Remove messaging handler to avoid implicit ZMQ dependency ([#235](https://github.com/edgexfoundry/go-mod-bootstrap/issues/235)) ([#9df977d](https://github.com/edgexfoundry/go-mod-bootstrap/commits/9df977d))
- Fix Secure MessageBus Secret validation for non-secure mode ([#233](https://github.com/edgexfoundry/go-mod-bootstrap/issues/233)) ([#f6c98ef](https://github.com/edgexfoundry/go-mod-bootstrap/commits/f6c98ef))
- Generate mock for latest SecretProvider interface ([#206](https://github.com/edgexfoundry/go-mod-bootstrap/issues/206)) ([#359809f](https://github.com/edgexfoundry/go-mod-bootstrap/commits/359809f))
- Use V2 Ping for health check ([#5bb40c1](https://github.com/edgexfoundry/go-mod-bootstrap/commits/5bb40c1))
- **secuirty:** remove retry config items from SecretStore config ([#248](https://github.com/edgexfoundry/go-mod-bootstrap/issues/248)) ([#6002097](https://github.com/edgexfoundry/go-mod-bootstrap/commits/6002097))
### Code Refactoring ♻
- Update ServiceInfo struct to be used by all services and add MaxRequestSize ([#9e3af34](https://github.com/edgexfoundry/go-mod-bootstrap/commits/9e3af34))
    ```
    BREAKING CHANGE:
    Service configuration has changed for all services
    ```
- Update calling GenerateConsulToken ([#212](https://github.com/edgexfoundry/go-mod-bootstrap/issues/212)) ([#e295a6e](https://github.com/edgexfoundry/go-mod-bootstrap/commits/e295a6e))
- Replace use of BurntSushi/toml with pelletier/go-toml ([#6c8f2b4](https://github.com/edgexfoundry/go-mod-bootstrap/commits/6c8f2b4))
- Expose ConfigVersion so services can use if needed ([#204](https://github.com/edgexfoundry/go-mod-bootstrap/issues/204)) ([#e966ad5](https://github.com/edgexfoundry/go-mod-bootstrap/commits/e966ad5))
- Set the Config Version when creating Config Client ([#201](https://github.com/edgexfoundry/go-mod-bootstrap/issues/201)) ([#615e600](https://github.com/edgexfoundry/go-mod-bootstrap/commits/615e600))
    ```
    BREAKING CHANGE:
    Configuration in Consul now under the `/2.0/` path
    ```
- Refactor ListenForCustomConfigChanges to avoid use of channel ([#187](https://github.com/edgexfoundry/go-mod-bootstrap/issues/187)) ([#cffb2fe](https://github.com/edgexfoundry/go-mod-bootstrap/commits/cffb2fe))
- Updated go.mod for tagged go-mod-secrets and fixed unittest ([#05db8a1](https://github.com/edgexfoundry/go-mod-bootstrap/commits/05db8a1))
- Add comment for new Type setting. ([#d2e6caa](https://github.com/edgexfoundry/go-mod-bootstrap/commits/d2e6caa))

<a name="v0.0.68"></a>
## [v0.0.68] - 2021-01-04
### Features ✨
- Enhance Timer to be used for timed loops beyond bootstrapping ([#141](https://github.com/edgexfoundry/go-mod-bootstrap/issues/141)) ([#ff8e38c](https://github.com/edgexfoundry/go-mod-bootstrap/commits/ff8e38c))

<a name="v0.0.67"></a>
## [v0.0.67] - 2021-01-04
### Bug Fixes 🐛
- Add setting the configured LogLevel ([#143](https://github.com/edgexfoundry/go-mod-bootstrap/issues/143)) ([#9cbc3d8](https://github.com/edgexfoundry/go-mod-bootstrap/commits/9cbc3d8))

<a name="v0.0.66"></a>
## [v0.0.66] - 2020-12-30
### Code Refactoring ♻
- Remove backward compatibility code ([#139](https://github.com/edgexfoundry/go-mod-bootstrap/issues/139)) ([#c10d266](https://github.com/edgexfoundry/go-mod-bootstrap/commits/c10d266))

<a name="v0.0.65"></a>
## [v0.0.65] - 2020-12-29
### Code Refactoring ♻
- Refactor to remove remote and file logging ([#138](https://github.com/edgexfoundry/go-mod-bootstrap/issues/138)) ([#d92118e](https://github.com/edgexfoundry/go-mod-bootstrap/commits/d92118e))

<a name="v0.0.62"></a>
## [v0.0.62] - 2020-12-20
### Code Refactoring ♻
- Secret Provider for all services ([#134](https://github.com/edgexfoundry/go-mod-bootstrap/issues/134)) ([#6cb9329](https://github.com/edgexfoundry/go-mod-bootstrap/commits/6cb9329))

<a name="v0.0.59"></a>
## [v0.0.59] - 2020-11-25
### Bug Fixes 🐛
- LoggingClientFrom handle nil case properly ([#c95d24f](https://github.com/edgexfoundry/go-mod-bootstrap/commits/c95d24f))

<a name="v0.0.58"></a>
## [v0.0.58] - 2020-11-19
### Features ✨
- Allow service to pass in initial logging client ([#3651de7](https://github.com/edgexfoundry/go-mod-bootstrap/commits/3651de7))

<a name="v0.0.57"></a>
## [v0.0.57] - 2020-10-28
### Bug Fixes 🐛
- Accept argument lists with a -r substring ([#dc0e6ea](https://github.com/edgexfoundry/go-mod-bootstrap/commits/dc0e6ea))

<a name="v0.0.50"></a>
## [v0.0.50] - 2020-10-14
### Bug Fixes 🐛
- Handle env override values which have the '=' character ([#4846fb7](https://github.com/edgexfoundry/go-mod-bootstrap/commits/4846fb7))

<a name="v0.0.41"></a>
## [v0.0.41] - 2020-09-29
### Bug Fixes 🐛
- Increase default startup duration to 60 seconds ([#0761e33](https://github.com/edgexfoundry/go-mod-bootstrap/commits/0761e33))

<a name="v0.0.37"></a>
## [v0.0.37] - 2020-07-30
### Bug Fixes 🐛
- Startup Duration and Interval never updated from default values ([#c35f13c](https://github.com/edgexfoundry/go-mod-bootstrap/commits/c35f13c))

<a name="v0.0.36"></a>
## [v0.0.36] - 2020-07-13
### Bug Fixes 🐛
- Configurable ip address for ListenAndServe, fixes [#83](https://github.com/edgexfoundry/go-mod-bootstrap/issues/83) ([#ec63238](https://github.com/edgexfoundry/go-mod-bootstrap/commits/ec63238))

<a name="v0.0.35"></a>
## [v0.0.35] - 2020-07-07
### Code Refactoring ♻
- **config:** Remove ClientMonitor from the ServiceInfo struct ([#efe9cb9](https://github.com/edgexfoundry/go-mod-bootstrap/commits/efe9cb9))

<a name="v0.0.33"></a>
## [v0.0.33] - 2020-06-01
### Bug Fixes 🐛
- Changed from using blank hostname to 0.0.0.0 ([#38f87ec](https://github.com/edgexfoundry/go-mod-bootstrap/commits/38f87ec))
- Don't use hostname for webserver ListenAndServe ([#6dbe24f](https://github.com/edgexfoundry/go-mod-bootstrap/commits/6dbe24f))

<a name="v0.0.32"></a>
## [v0.0.32] - 2020-05-29
### Bug Fixes 🐛
- Allow overrides that have empty/blank value ([#5497010](https://github.com/edgexfoundry/go-mod-bootstrap/commits/5497010))

<a name="v0.0.31"></a>
## [v0.0.31] - 2020-04-29
### Bug Fixes 🐛
- **config:** Ignore first config changes notification on start-up ([#2834834](https://github.com/edgexfoundry/go-mod-bootstrap/commits/2834834))

<a name="v0.0.30"></a>
## [v0.0.30] - 2020-04-21
### Features ✨
- **environment:** Perform case insensitive comparision for override names ([#3d7becb](https://github.com/edgexfoundry/go-mod-bootstrap/commits/3d7becb))

<a name="v0.0.28"></a>
## [v0.0.28] - 2020-04-14
### Bug Fixes 🐛
- **config:** Change UpdatedStream to be defined as `chan struct{}` ([#6d2e43b](https://github.com/edgexfoundry/go-mod-bootstrap/commits/6d2e43b))

<a name="v0.0.26"></a>
## [v0.0.26] - 2020-03-31
### Bug Fixes 🐛
- **logging:** Logger not configured properly ([#017c944](https://github.com/edgexfoundry/go-mod-bootstrap/commits/017c944))

<a name="v0.0.25"></a>
## [v0.0.25] - 2020-03-30
### Features ✨
- Add Self seeding, env var overrides, cmd-line options per ADR 0005-Service-Self-Config.md ([#59](https://github.com/edgexfoundry/go-mod-bootstrap/issues/59)) ([#e56334c](https://github.com/edgexfoundry/go-mod-bootstrap/commits/e56334c))

<a name="v0.0.24"></a>
## [v0.0.24] - 2020-03-26
### Bug Fixes 🐛
- Add retry loop for secret client if initial token is invalid ([#60](https://github.com/edgexfoundry/go-mod-bootstrap/issues/60)) ([#ecac4d1](https://github.com/edgexfoundry/go-mod-bootstrap/commits/ecac4d1))

<a name="v0.0.13"></a>
## [v0.0.13] - 2020-02-04
### Bug
- **config:** Embedded types do not work with package we use to pull from Consul ([#38](https://github.com/edgexfoundry/go-mod-bootstrap/issues/38)) ([#2d9fcd4](https://github.com/edgexfoundry/go-mod-bootstrap/commits/2d9fcd4))

<a name="v0.0.12"></a>
## [v0.0.12] - 2020-01-31
### Code Refactoring ♻
- **registry:** Integrate new Configuration & Registry clients ([#915c058](https://github.com/edgexfoundry/go-mod-bootstrap/commits/915c058))

