## [1.4.1](https://github.com/knitli/toolshed/compare/@knitli/openapi-mcp-v1.4.0...@knitli/openapi-mcp-v1.4.1) (2026-10-08)


### Bug Fixes

* **ctx:** address shellcheck in scan-context-files hook ([f6c0d79](https://github.com/knitli/toolshed/commit/f6c0d7957d923c8949d9f1d5b638acae6e9218f5))
* **event-gateway:** address dependency and quality review findings ([e08ea37](https://github.com/knitli/toolshed/commit/e08ea37e57b04fec0d01b35384af746d3dce1656))
* **event-gateway:** address packaged recovery review findings ([72f59e8](https://github.com/knitli/toolshed/commit/72f59e8b433aa9c84b5eeb609ee43c394f9cb49d))
* **event-gateway:** allow trusted control pin rotation ([60f1670](https://github.com/knitli/toolshed/commit/60f1670c7f5a573af3a2714b3b65e4dee511dc1b))
* **event-gateway:** bind helper probes to checkpoint binaries ([271c5f4](https://github.com/knitli/toolshed/commit/271c5f4f550dd493c175deb546eb19c3cbf33b8a))
* **event-gateway:** clarify controlled qualification fixture inputs ([c2afdc6](https://github.com/knitli/toolshed/commit/c2afdc69dc8b2ee858a13f5cc6814421fa705c57))
* **event-gateway:** classify malformed content type headers ([03ea75e](https://github.com/knitli/toolshed/commit/03ea75edfd276c126abc5da1dfa110c9e753bedd))
* **event-gateway:** close cloud input validation gaps ([4467aee](https://github.com/knitli/toolshed/commit/4467aeede370c6fb776b0647502b89dc786ccd59))
* **event-gateway:** contain submission capacity refusal ([5ebe067](https://github.com/knitli/toolshed/commit/5ebe0670ecc0286f284185a0f13907f40e5ed6dc))
* **event-gateway:** document fixed SQL identifiers ([761dede](https://github.com/knitli/toolshed/commit/761dede25c7fc8e1cabe4e648c8247d823fac1fd))
* **event-gateway:** enforce canonical origins and response invariants ([07bc4ef](https://github.com/knitli/toolshed/commit/07bc4ef32c82a2b69708ccb9804ee374eeb920c2))
* **event-gateway:** enforce optional consumer generation fences ([5c3f028](https://github.com/knitli/toolshed/commit/5c3f028c534c85be23b5e3888b29bf7d2ab949d2))
* **event-gateway:** enforce per-agent session admission ([7149591](https://github.com/knitli/toolshed/commit/714959182cc913988d1d9e47819b3faf09f59b6c))
* **event-gateway:** fence native permits and inherited channels ([06c608f](https://github.com/knitli/toolshed/commit/06c608fb4fff2a5124ec25f4906a4d6772e17bfd))
* **event-gateway:** finish trusted refresh after status failures ([b9e3725](https://github.com/knitli/toolshed/commit/b9e3725f5f8b42a39a95d6756beef0b148628922))
* **event-gateway:** give permit-expiry qualification its own deadline ([3001c0b](https://github.com/knitli/toolshed/commit/3001c0b9066cbe18b02d53803cd6a5a0938d7632))
* **event-gateway:** give primary wait its own deadline ([27ad643](https://github.com/knitli/toolshed/commit/27ad6438e932e06fb1e0667cb2b88b5a07299e53))
* **event-gateway:** identify failed contract publications safely ([d55d3ee](https://github.com/knitli/toolshed/commit/d55d3ee60c3a0aafdcdb8f8e2523ba8d3a1b0f60))
* **event-gateway:** isolate malformed status responses ([5160b4d](https://github.com/knitli/toolshed/commit/5160b4d32cfc86b25dd27405b5876af83d7cc798))
* **event-gateway:** keep reusable secrets out of PR CI ([e6fcf48](https://github.com/knitli/toolshed/commit/e6fcf488a57df9adea688e07ad033b49987db753))
* **event-gateway:** make trusted contract rotations resilient ([52359a1](https://github.com/knitli/toolshed/commit/52359a1fe5a37be05faeef2932eaefa0fac652a2))
* **event-gateway:** persist required receipt mode before native start ([5599126](https://github.com/knitli/toolshed/commit/55991265640f94f444562108629f64dfc065d6b2))
* **event-gateway:** preserve and fence recovery evidence ([3e81bf9](https://github.com/knitli/toolshed/commit/3e81bf954abfa2fcabcc237a0ae63890277fb0a3))
* **event-gateway:** preserve refusal codes and enrollment clock bounds ([b8b5cd5](https://github.com/knitli/toolshed/commit/b8b5cd5bb3ae9124d07b9dc982f3016219783d0a))
* **event-gateway:** preserve reviewer signal uncertainty ([8712391](https://github.com/knitli/toolshed/commit/8712391408582d7c1e4eaa4ab678fd9a2bfa4e82))
* **event-gateway:** preserve strict receipt mode type checks ([1eacdfe](https://github.com/knitli/toolshed/commit/1eacdfecf322a8a571dd4f817de283cca8eb17ba))
* **event-gateway:** qualify native preparation failure safely ([8752f0d](https://github.com/knitli/toolshed/commit/8752f0df8302ac12f2cbcb3137f46f60c0550fda))
* **event-gateway:** reap owned qualification process groups ([5428a63](https://github.com/knitli/toolshed/commit/5428a63e4ff25be4fbfe9d29dc7e06b0f4fc8a7f))
* **event-gateway:** recover exact receipts across lease renewal ([6706834](https://github.com/knitli/toolshed/commit/6706834378f946b1d0d5c0885f6054c83c47798e))
* **event-gateway:** recover observer input and socket cleanup ([80abc5a](https://github.com/knitli/toolshed/commit/80abc5a37cb5c16e4e6c77cb0d46425c7746ebb9))
* **event-gateway:** refresh delayed claims and validate source before export ([5960895](https://github.com/knitli/toolshed/commit/5960895a55a0bcf5eb597e22eb1f910c26ea26d4))
* **event-gateway:** reject malformed configuration and enrollment types ([40e8eab](https://github.com/knitli/toolshed/commit/40e8eab1a94d931fdf4f81a968d400bf07bab4aa))
* **event-gateway:** reject unsupported turn IDs before native submit ([f0876e7](https://github.com/knitli/toolshed/commit/f0876e785466cfc26a562fed2f7a9788407a0729))
* **event-gateway:** remediate Codacy docs/complexity findings ([49445b6](https://github.com/knitli/toolshed/commit/49445b6a6786f6ab959c835e9905651472d41795))
* **event-gateway:** retain exact start proof when native polling fails ([afb6c17](https://github.com/knitli/toolshed/commit/afb6c17a067d6bd990f7b20ac3c40d609ada6814))
* **event-gateway:** retain replay checks under optimization ([ae6ed9d](https://github.com/knitli/toolshed/commit/ae6ed9dc5a57467a42cadf6f6aa636131a65bbe9))
* **event-gateway:** scope qualification analyzer annotations ([6020a31](https://github.com/knitli/toolshed/commit/6020a317c3b6ac4e98476d9d2871f32b18844144))
* **event-gateway:** stop disconnected witness readers and close logs ([93566c9](https://github.com/knitli/toolshed/commit/93566c958e73d892d10c3cafe2b8180fea2a8a2e))
* **event-gateway:** verify contracts from absolute checkout path ([ef5e9fd](https://github.com/knitli/toolshed/commit/ef5e9fd6497417bd1ffffbaef22d9da8724d02e6))
* **marketplace:** pin third-party actions to commit SHAs ([2da2343](https://github.com/knitli/toolshed/commit/2da2343e6e99fdbf0d3dfc47fdb5d089ae97f384))
* **openapi-mcp:** collapse fifo helper formatting ([4a78407](https://github.com/knitli/toolshed/commit/4a78407206c11039ca15f0b0f8c186d798fd9ee3))
* **openapi-mcp:** linear-time credential redaction and fifo nosemgrep ([9d6f939](https://github.com/knitli/toolshed/commit/9d6f939ddbc3805fca17836fab14da23c5eb69d6))
* **openapi-mcp:** remediate Codacy findings in remaining tests ([ccbacc7](https://github.com/knitli/toolshed/commit/ccbacc74f2e8e98357c394396a40590faa86ca06))
* **openapi-mcp:** remediate Codacy findings in stdio-server tests ([8fb896c](https://github.com/knitli/toolshed/commit/8fb896c8b4f8aba11aab1054f60302c52618e1e8))
* **openapi-mcp:** remediate Codacy security findings in sources ([c716f9e](https://github.com/knitli/toolshed/commit/c716f9e694fcff586132fcf0f70038ab8370e9ea))


### Features

* **event-gateway:** add closed cloud control-plane client ([aa67e74](https://github.com/knitli/toolshed/commit/aa67e747b41e0244f66b5ee5504dc85c7ddbb9f8))
* **event-gateway:** add disabled local gateway foundation ([184734c](https://github.com/knitli/toolshed/commit/184734ce571885e46a2c300432b31e536b4491a3))
* **event-gateway:** anchor native receipts across app-server restart ([523405b](https://github.com/knitli/toolshed/commit/523405be0baa09f414266997a7d502494752f4a8))
* **event-gateway:** bind explicit v3 receipts to bridge generation ([1605074](https://github.com/knitli/toolshed/commit/1605074cb701cdcda4ddd8b35cca90f2b36745c1))
* **event-gateway:** package native reader and prove combined recovery ([f99f34f](https://github.com/knitli/toolshed/commit/f99f34fd88775649a9335fda3537d222b11b3d00))
* **event-gateway:** persist and reconcile direct native start ACKs ([af1d569](https://github.com/knitli/toolshed/commit/af1d569560f637407357829a92276c999a7cd3af))
* **event-gateway:** qualify a closed native Codex bridge ([c800be8](https://github.com/knitli/toolshed/commit/c800be876d240321bd3e6d1f177b15fa4ad5e855))
* **event-gateway:** reconcile recorded native input in two phases ([83bd975](https://github.com/knitli/toolshed/commit/83bd9751b4616298563f8e633bb71520f0dbf347))
* **event-gateway:** settle definite no-start attempts before retry ([4d44182](https://github.com/knitli/toolshed/commit/4d4418231d1c5c3492c52b173b118476d9b780fb))
* **mkt:** Add codacy to environment with fnox ([9f914d5](https://github.com/knitli/toolshed/commit/9f914d5c2124b5fa56523990aeb75a19ff5ac8a0))

# [1.4.0](https://github.com/knitli/toolshed/compare/@knitli/openapi-mcp-v1.3.1...@knitli/openapi-mcp-v1.4.0) (2026-09-25)


### Bug Fixes

* **openapi-mcp:** tighten batched operation verification ([5bdf237](https://github.com/knitli/toolshed/commit/5bdf237fe1710b8bccfdbdb8a2321870730fc8ce))


### Features

* **openapi-mcp:** batch operation reads during complete-release verification ([37c55a5](https://github.com/knitli/toolshed/commit/37c55a569b6f1e1ab0b3a705b36307198863e83b))
* **openapi-mcp:** bound operation batches by the catalog bundle cap ([eab33dd](https://github.com/knitli/toolshed/commit/eab33dd43f7e05b3a1b03b1af7f89c9e2210c5ef))

## [1.3.1](https://github.com/knitli/toolshed/compare/@knitli/openapi-mcp-v1.3.0...@knitli/openapi-mcp-v1.3.1) (2026-09-21)


### Bug Fixes

* **openapi-mcp:** ignore OpenAPI specification extensions on schemas ([73a2a36](https://github.com/knitli/toolshed/commit/73a2a36daf150f812b87b7b6c9e584c3906c62b7))

# [1.3.0](https://github.com/knitli/toolshed/compare/@knitli/openapi-mcp-v1.2.1...@knitli/openapi-mcp-v1.3.0) (2026-09-13)


### Features

* **openapi-mcp:** expose manifest authentication ([#30](https://github.com/knitli/toolshed/issues/30)) ([4c874ce](https://github.com/knitli/toolshed/commit/4c874ce7a81c1a1dacbef2c6887749d834525c52))

## [1.2.1](https://github.com/knitli/toolshed/compare/@knitli/openapi-mcp-v1.2.0...@knitli/openapi-mcp-v1.2.1) (2026-09-12)


### Bug Fixes

* **openapi-mcp:** add slice --optional to relax always-required Graph properties ([3075f73](https://github.com/knitli/toolshed/commit/3075f7382beda338f2e4eecf5f16b3a456d8fdc1))
* **openapi-mcp:** enforce anyOf discriminators and keep the bare-discriminator shape check ([61857f5](https://github.com/knitli/toolshed/commit/61857f587100d25f43426f9309ebf5fcf9ed1c1b))
* **openapi-mcp:** treat an inheritance-style discriminator as informational ([0dbb326](https://github.com/knitli/toolshed/commit/0dbb326a2e4b0e1efb331ef0c8c3f18714681290))

# [1.2.0](https://github.com/knitli/toolshed/compare/@knitli/openapi-mcp-v1.1.0...@knitli/openapi-mcp-v1.2.0) (2026-09-11)


### Bug Fixes

* **openapi-mcp:** honor slice's node limit, selectors, and ref closure ([97215cc](https://github.com/knitli/toolshed/commit/97215cca36f0502b6c1991237e72085653cc3d64)), closes [#28](https://github.com/knitli/toolshed/issues/28) [#28](https://github.com/knitli/toolshed/issues/28)
* **openapi-mcp:** make slice's keys= budget note conditional, pin operations= to HTTP methods ([aeed8c8](https://github.com/knitli/toolshed/commit/aeed8c84bb1175e96d7912050678b6660a26b09a))
* **openapi-mcp:** print slice's real compile-release maxDocumentKeys default ([99c616c](https://github.com/knitli/toolshed/commit/99c616c2fc8dd796bc7e09543ac0c60e7887b8a6))


### Features

* **openapi-mcp:** slice command selects operations by tag or id and prunes components ([e48fb7b](https://github.com/knitli/toolshed/commit/e48fb7bae2ac08bec7bbb4f19c23d441a893b770))

# [1.1.0](https://github.com/knitli/toolshed/compare/@knitli/openapi-mcp-v1.0.0...@knitli/openapi-mcp-v1.1.0) (2026-09-06)


### Features

* **openapi-mcp:** expose complete catalog release admission ([933a843](https://github.com/knitli/toolshed/commit/933a84368286b9b4ee0480ff9f4af0ae20fc6d91))

# 1.0.0 (2026-09-05)


### Bug Fixes

* add @semantic-release/npm as explicit devDependency ([d7a216f](https://github.com/knitli/toolshed/commit/d7a216f2d145faf3201bf05967019fab62c76ab8))
* address code review — npmScope in shared, --new/--check guard, CI permissions ([cab092f](https://github.com/knitli/toolshed/commit/cab092fc73095cded6ea19887733922858b7c8e0))
* apply code review fixes to generate.mjs, validate.yml, and release.yml ([894b7ea](https://github.com/knitli/toolshed/commit/894b7ea631f41c3f63e49eb0c691abbe07323925))
* **ci:** add shell script expected by knitli-agents ([b756d75](https://github.com/knitli/toolshed/commit/b756d75e8fe03e6f5b58fa6f10f784ba7e65d7de))
* **codeweaver,ctx:** Corrected issue with malformed plugin manifests ([07714f5](https://github.com/knitli/toolshed/commit/07714f514bbf9739160dfc3eae48b39234be260f))
* **codeweaver:** Corrected flawed env variable configuration ([1a50d42](https://github.com/knitli/toolshed/commit/1a50d427674941199d6da806f613b2330ef68685))
* **codeweaver:** corrected invalid manifest variable ([6b89e5f](https://github.com/knitli/toolshed/commit/6b89e5f019cb519496b7b6405b3bc9a9cf72e6d1))
* comply with marketplace.json schema (additionalProperties: false on PluginEntry) ([d9cd49b](https://github.com/knitli/toolshed/commit/d9cd49bfc340f0c5ab02b1f5eb77b3584949f5b6))
* **ctx:** Fix an issue where in certain situations an LLMs meta-thinking can cause an infinite loop ([38c9422](https://github.com/knitli/toolshed/commit/38c9422c1d90f800768db89e62434aa8b83cbf87))
* **marketplace:** match validation workflow in review gate ([fb86279](https://github.com/knitli/toolshed/commit/fb86279e8479afe0bd9e767b90ff874c61e1d047))
* **marketplace:** remove some filters on marketplace.shared ([4169f3a](https://github.com/knitli/toolshed/commit/4169f3a9c9a586baae9ccb22aad44382a26f9556))
* **marketplace:** Update release workflow to use npx for semantic-release ([49944f9](https://github.com/knitli/toolshed/commit/49944f949906cff441f327fc407a9d438d71a923))
* **marketplace:** use bunx for semantic-release and fix tag format to match existing tags ([e8b3da3](https://github.com/knitli/toolshed/commit/e8b3da3be64eb3f8a3275193835b886962424d29))
* **openapi-mcp:** align portable runtime contract ([4069199](https://github.com/knitli/toolshed/commit/406919942b27243e1876ebf99e965829ea5bb2c7))
* **openapi-mcp:** atomic wx keygen writes close symlink overwrite hole ([6f02f9c](https://github.com/knitli/toolshed/commit/6f02f9c3552d684a6727b5fb55c5feeabb3ab561))
* **openapi-mcp:** avoid release adapter startup deadlock ([2446f41](https://github.com/knitli/toolshed/commit/2446f4145d82d020a6bd19903b362d977856f42a))
* **openapi-mcp:** bind mapped reference reads ([5cecde9](https://github.com/knitli/toolshed/commit/5cecde951f8407ecdd09b4ec7505f986b66d8ae4))
* **openapi-mcp:** bind prepared calls and action receipts ([2eaf94c](https://github.com/knitli/toolshed/commit/2eaf94c35f7e8a5b17f58fc9b976401efc96abd6))
* **openapi-mcp:** bound catalog transport data ([06b5555](https://github.com/knitli/toolshed/commit/06b5555cb79f85b4354ef90c27c65b370c9defcc))
* **openapi-mcp:** bound emitted sqlite reread ([562a277](https://github.com/knitli/toolshed/commit/562a27707c6b2e9c00201b196e638c288dd1587c))
* **openapi-mcp:** bound remaining v4 resource reads ([d284d42](https://github.com/knitli/toolshed/commit/d284d42ff6fa6a1f2811d6b53ef6cbeace970f22))
* **openapi-mcp:** bun 1.4 floor, keygen rollback, clean arg errors, acronym word-split ([8647053](https://github.com/knitli/toolshed/commit/86470534cb6453d2683f783d8f44caba15a05961)), closes [oven-sh/bun#32498](https://github.com/oven-sh/bun/issues/32498)
* **openapi-mcp:** close recovery and record-bound races ([be83662](https://github.com/knitli/toolshed/commit/be83662709d3323019af0781f2997c8d7c4d2fdb))
* **openapi-mcp:** close reviewed trust boundaries ([45fbda0](https://github.com/knitli/toolshed/commit/45fbda0880b1cfc2c4951ac12c9b79a2b735b413))
* **openapi-mcp:** close v4 namespace race gaps ([d04964e](https://github.com/knitli/toolshed/commit/d04964e623b89e5ba222db43ff428b08fbac4ff0))
* **openapi-mcp:** exclude slash-scoped release fallbacks ([fda132a](https://github.com/knitli/toolshed/commit/fda132aadd7eca4d4068a8811d9f957dfa9c82c8))
* **openapi-mcp:** fail closed on ambiguous action effects ([dda4da4](https://github.com/knitli/toolshed/commit/dda4da4e834cbd9cb4f92217f2426ef470e5c41c))
* **openapi-mcp:** fail closed on per-operation servers overrides ([46bbec7](https://github.com/knitli/toolshed/commit/46bbec769eb1ffdc84a0a0ea86902db10f470fd8))
* **openapi-mcp:** finalize bun sqlite statements ([b675a54](https://github.com/knitli/toolshed/commit/b675a54967088266b6f1f70888c47f3357ef7a6c))
* **openapi-mcp:** hard-pin $batch to write/high before the method check ([a1e723f](https://github.com/knitli/toolshed/commit/a1e723f96556c947af062faac85e55283a61a670))
* **openapi-mcp:** harden manifest generation trust state ([28191be](https://github.com/knitli/toolshed/commit/28191bec9d7dc3d69f0ffef5f5e63565a8020e62))
* **openapi-mcp:** harden runtime catalog inputs ([76ff205](https://github.com/knitli/toolshed/commit/76ff205c5aa0f81248eed41cd4061974b405d67c))
* **openapi-mcp:** harden search bounds and persistence ([eb1e547](https://github.com/knitli/toolshed/commit/eb1e547f9a65d55f902d6fb9251ff391deaf3c27))
* **openapi-mcp:** harden v4 compilation and publication ([86ab86b](https://github.com/knitli/toolshed/commit/86ab86bedd67c9bacbecd3fdef271c6286ca5b41))
* **openapi-mcp:** keep schema creation inside the compile transaction ([5e02098](https://github.com/knitli/toolshed/commit/5e020982a62168d6fbcad2e6788e57563e706f0b))
* **openapi-mcp:** make Graph safety and $batch invariants discriminate ([ff62f6d](https://github.com/knitli/toolshed/commit/ff62f6d0a791fe01c41b559fa60e83cbe4bc53d2))
* **openapi-mcp:** make JSON-dispatch test discriminate its branch ([63810ba](https://github.com/knitli/toolshed/commit/63810ba24029bd71f0f96baf13a0b7b1ead2584e))
* **openapi-mcp:** preserve schema resource semantics ([0ea7db2](https://github.com/knitli/toolshed/commit/0ea7db215c1bea8994b612637e4eb936570b000f))
* **openapi-mcp:** preserve verified search state ([a5df3ee](https://github.com/knitli/toolshed/commit/a5df3eeafe69c8f46b50389ffae5eb5bba20dd9b))
* **openapi-mcp:** reject hidden canonical properties ([1d49e63](https://github.com/knitli/toolshed/commit/1d49e634de35fffb858e974e22eaf179ae932e6a))
* **openapi-mcp:** reject reserved auth headers and roll back token writes ([c10d858](https://github.com/knitli/toolshed/commit/c10d858379d318555a23bdf96c0b15b57db175d4))
* **openapi-mcp:** reject reused filesystem identities ([81f2ef7](https://github.com/knitli/toolshed/commit/81f2ef7495d7674c332d472d899d5aa6a022b0ed))
* **openapi-mcp:** release sqlite handles on close ([b44eb67](https://github.com/knitli/toolshed/commit/b44eb67a30b0631a39a50c6cee86978deb25c01f))
* **openapi-mcp:** restore scoped release classification ([089b012](https://github.com/knitli/toolshed/commit/089b0125e628939015b36124e0a54cb8046a183e))
* **openapi-mcp:** restore scoped release rules ([a2a2a1a](https://github.com/knitli/toolshed/commit/a2a2a1a79db22b8f0aa19369062bbcaa3947c670))
* **openapi-mcp:** retire bootstrap and wait for registry visibility ([16f7847](https://github.com/knitli/toolshed/commit/16f7847b0043a4450368f6b200be17828d144a95))
* **openapi-mcp:** scope read overrides per API and stop dropping body contracts ([8b72b96](https://github.com/knitli/toolshed/commit/8b72b9689d248cc5bf40bec4358754853c24fdf0))
* **openapi-mcp:** skip path specification extensions ([8d37a25](https://github.com/knitli/toolshed/commit/8d37a25401e42a5db136f677e8a32193350afe62))
* **openapi-mcp:** tighten CLI test assertions to check specific error content ([93df29c](https://github.com/knitli/toolshed/commit/93df29cf87786a1abd6f5fe1921bc206ae215692))
* **openapi-mcp:** use a persistent generation mutex ([a38551c](https://github.com/knitli/toolshed/commit/a38551cf0d88cd5beac768dd31205bd92ff010ad))
* **openapi-mcp:** validate referenced paths and exports ([7e344fa](https://github.com/knitli/toolshed/commit/7e344faf6606e05903dded0a9909eee47e1f4292))
* **openapi-mcp:** validate startup before admission and preserve response envelopes ([6eef6f5](https://github.com/knitli/toolshed/commit/6eef6f507e020d63a000548951b739c81d20059d))
* **openapi-mcp:** verify emitted v4 sqlite stage ([165fbfb](https://github.com/knitli/toolshed/commit/165fbfbb2bb656cf7ea65ae14809c4e8c6d14b8a))
* **openapi-mcp:** verify releases before search admission ([cc4138a](https://github.com/knitli/toolshed/commit/cc4138a798738d359f41eb88aafcb574de4d15e2))
* **openapi-mcp:** version signed records and harden serialization ([4de8858](https://github.com/knitli/toolshed/commit/4de8858416693422a6c22a3dead8e41403a65801))
* **openapi-mcp:** write private key with 0600 permissions ([7b07f2d](https://github.com/knitli/toolshed/commit/7b07f2da9c766ced6544c0bcc0a5f66fce5e42c7))
* testing marketplace fix for path resolution ([8e1a7e9](https://github.com/knitli/toolshed/commit/8e1a7e9e58f36b717dafcdd7122eec7ab87943cf))
* testing marketplace fix for path resolution ([86b8bc2](https://github.com/knitli/toolshed/commit/86b8bc26205ae36b9c29b4faa9f1abbffc95aada))
* version sync and simplify generation system ([62767e3](https://github.com/knitli/toolshed/commit/62767e3926f2a8771b4d05fa8f1cf361d1233eeb))


### Features

* add decision-accountability (Jacob Dietle) for testing ([08f5a4b](https://github.com/knitli/toolshed/commit/08f5a4b8b4cdf77343400d8ff85760ee56209b59))
* Add strip-ansi plugin for clean input/output ([d9af215](https://github.com/knitli/toolshed/commit/d9af2150ddab2178210bec8eb86df3edbe9f1703))
* central manifest generator — marketplace.json as source of truth ([65d23a5](https://github.com/knitli/toolshed/commit/65d23a5001184312ea47c286a86f29bc0b14d2f0))
* **ctx:** Add ability to pass arguments to ctx commands to direct behavior ([7689926](https://github.com/knitli/toolshed/commit/76899260e2ed5eae501fc9278e88934fa6ac6765))
* **ctx:** add jules to context-files.ini ([41e5bd1](https://github.com/knitli/toolshed/commit/41e5bd1e874163cb63291bab3e63a72541c26bfa))
* **ctx:** move ctx plugin into plugins/ctx/ ([62a4194](https://github.com/knitli/toolshed/commit/62a41945863fdf5dd67e8427bc8f050d8ddf129b))
* **da:** add decision-accountability plugin for testing ([fa177fb](https://github.com/knitli/toolshed/commit/fa177fba4a850d5efc6a87209e18d930f2fbabd1))
* **marketplace:** dev tooling updates, added pre-commit lints/hooks with hk ([4167337](https://github.com/knitli/toolshed/commit/4167337990c2ac484685485b9d8f42bf0d2e8e9c))
* **marketplace:** retire ctx and codeweaver, remove decision-accountability ([1c65d48](https://github.com/knitli/toolshed/commit/1c65d489dd953a037bd07b7bee5161ff99cf10ac))
* **marketplace:** scope-authoritative releases + marketplace versioning ([24d7ee5](https://github.com/knitli/toolshed/commit/24d7ee5182bfbf16fafdf680171c10457a3defe5))
* **marketplace:** support commit scopes for non-plugin workspaces ([9f74a27](https://github.com/knitli/toolshed/commit/9f74a27831ff0ebdd432a74cd6b6aa14562ce872))
* **marketplace:** wire openapi-mcp npm release ([31ba9e8](https://github.com/knitli/toolshed/commit/31ba9e8109b87bdc1d6e6bf7fdb4bbfec2079396))
* **mkt:** scope aliases for commitlint and release routing ([3b44c97](https://github.com/knitli/toolshed/commit/3b44c9725f6606b8968f61318c895602b3cd16f5))
* **openapi-mcp:** add call preparation foundations ([f8ebb7a](https://github.com/knitli/toolshed/commit/f8ebb7ad878b4427be1d2ef209d17332c55f3539))
* **openapi-mcp:** add canonical signed-data primitives ([2398d88](https://github.com/knitli/toolshed/commit/2398d880aee6aaab7a3e33c4154ec946e24a6421))
* **openapi-mcp:** add catalog store conformance contract ([2283779](https://github.com/knitli/toolshed/commit/228377901c87f995fc5ddcbcb8805778cef53576))
* **openapi-mcp:** add compile and keygen CLI ([9053d92](https://github.com/knitli/toolshed/commit/9053d92b898bacdc73fae2d91e8331f8ead91902))
* **openapi-mcp:** add explicit local authentication profiles ([556c0c6](https://github.com/knitli/toolshed/commit/556c0c6f1adf9301f356244e05f3b9f4cdd1ab12))
* **openapi-mcp:** add package scaffold and SQLite artifact schema ([7a52981](https://github.com/knitli/toolshed/commit/7a5298163c3c48bb0386e403d1ab624b21c5fa41))
* **openapi-mcp:** add verified search and schema resolution ([4572c16](https://github.com/knitli/toolshed/commit/4572c1687849c572a743ba830a8cd345059e312d))
* **openapi-mcp:** assemble the compiled SQLite artifact ([9ffe672](https://github.com/knitli/toolshed/commit/9ffe672874f3705a7d30608990a3857d929a2e42))
* **openapi-mcp:** authorize exact action digests ([6017987](https://github.com/knitli/toolshed/commit/6017987bef969896b052950414c43af06653f3f6))
* **openapi-mcp:** classify operation safety and risk with explicit overrides ([2bcdd16](https://github.com/knitli/toolshed/commit/2bcdd16db5e1c26393ada73c5c9754fdd167f621))
* **openapi-mcp:** compile immutable signed v4 releases ([0979751](https://github.com/knitli/toolshed/commit/097975171f7b35248d0067b893188a0c37c6c71e))
* **openapi-mcp:** complete verified stdio and release integration ([921c312](https://github.com/knitli/toolshed/commit/921c312a34dd566aa477ca7dd9a092e08c97ba5d))
* **openapi-mcp:** define portable runtime contract ([7ea824a](https://github.com/knitli/toolshed/commit/7ea824a45e990e1ccbd0df9910f50aea52d16769))
* **openapi-mcp:** enforce guarded single-use HTTP dispatch ([78a1264](https://github.com/knitli/toolshed/commit/78a1264321315a57b794184d868b9b3ee716013c))
* **openapi-mcp:** extract thin operation records with unresolved refs ([efbd68c](https://github.com/knitli/toolshed/commit/efbd68cf8201177fe32f0a65dfd79e4b2afe061b))
* **openapi-mcp:** load OpenAPI documents from YAML or JSON ([3e27a1d](https://github.com/knitli/toolshed/commit/3e27a1d772fef9228b2176da9dfd76f06ecd6d0e))
* **openapi-mcp:** map operations to upstream permissions and tier risk ([26d8a2f](https://github.com/knitli/toolshed/commit/26d8a2f462be4c42bdf17eeab2fb7987422ccfc6))
* **openapi-mcp:** mount multiple APIs into one artifact ([5055b5d](https://github.com/knitli/toolshed/commit/5055b5d4e04a0538c39b575d2a72c801cecf7427))
* **openapi-mcp:** prepare and revalidate exact API calls ([2efd0a4](https://github.com/knitli/toolshed/commit/2efd0a468e5ba2e0784b7fa7b951ea1c18d35c31))
* **openapi-mcp:** publishable package metadata and README ([9907490](https://github.com/knitli/toolshed/commit/9907490f216aacdd391011872584012fadeb463e))
* **openapi-mcp:** run on node and bun via node:sqlite and fs portability ([68b82ac](https://github.com/knitli/toolshed/commit/68b82aca00fd8fe3fdfab37af892ad5c6a4552b9))
* **openapi-mcp:** sign and verify compiled artifacts with ed25519 ([110859f](https://github.com/knitli/toolshed/commit/110859fa79bf864f1e26ccf82828921dbe9e7086))
* **openapi-mcp:** store component schemas with refs unresolved ([4e7318a](https://github.com/knitli/toolshed/commit/4e7318af9651c9b7051934a2d5c825ee954e99b4))
* **openapi-mcp:** verify subcommand, file-based keygen, clean cli errors ([df5d211](https://github.com/knitli/toolshed/commit/df5d21108ef2c4dc76da2b2daefbcaada78bf454))
* **openapi-mcp:** verify v4 manifests and logical records ([001433d](https://github.com/knitli/toolshed/commit/001433d98b5c3423ff5e7ce1afb3ab4eb6bdb86b))
* **openapi-mcp:** word-split search_text fts column, format v3 ([1f81324](https://github.com/knitli/toolshed/commit/1f8132404065fabd88ead77794044a97fae33534))
* **repo:** Add dev tools with mise, new issue template for codeweaver plugin ([7e97897](https://github.com/knitli/toolshed/commit/7e9789743ad37658df7782a4545bc0851382c3bd))
* restructure toolshed package and plugins for enhanced organization ([7aa85ab](https://github.com/knitli/toolshed/commit/7aa85ab08cec763b377694951f5d8808a94f3857))
* **strip-ansi:** Add MCP screening for malicious ansi escape characters ([c38e0da](https://github.com/knitli/toolshed/commit/c38e0da5fb6c2c0e97dab28ba0df0295a732603c))
