
<a name="Bootstrap Go Mod Changelog"></a>
## Bootstrap Module (in Go)
[Github repository](https://github.com/edgexfoundry/go-mod-bootstrap)

## [2.0.0] - 2021-06-30
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

