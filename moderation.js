const instances = new Map();

class ModerationInfo {
    constructor(name, status, reason) {
        this.name = name;
        this.status = status;
        this.reason = reason;
    }

}

function addInfo(sha256, instance, status, reason) {
    instances.set(sha256, new ModerationInfo(instance, status, reason));
}

async function getInfo(instance) {
    return instances.get(await sha256hash(instance.toLowerCase()));
}

async function sha256hash(string) {
    const hashArray = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(string));
    return Array.from(new Uint8Array(hashArray)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

addInfo('def4d2e153204d0ae1ded5b6ae6c35e7777eda93bf39da7bc53669ac13c8a129', 'dev-wiki.de', 'limited', 'Not properly moderated, admin seems to empathize with corona myths.');
addInfo('3542c488b41ce94a2cf9737bfe67c35252941a42af092ac4078634bc36578491', 'feminism.lgbt', 'limited', 'suspicious activity');
addInfo('7c17b88f4b78606d5094cea655284679a380525cd7642a6c1ef24de5a0cc2a24', 'getwild.online', 'limited', 'dedicated to porn, not properly enforcing nsfw');
addInfo('77a0b101a224534a7bc7db793f2670431a3ff414d9bac23abfd7c38ba3e35096', 'gs.kawa-kun.com', 'limited', 'Considered being lawless');
addInfo('d886ef4cb80c77e2638c4f1bc162d06052f0b6d70428eee116bb52d93ec4bd6b', 'humblr.social', 'limited', 'Instance-wide Content Warning');
addInfo('4d13e80e6cd7863d836618a0ee08e9f4b66d28671b9ec942f2b648177e9f83e7', 'myfreecams.com', 'limited', 'Instance-wide Content Warning');
addInfo('e7c641cf9cd8b5c4513e22d0dfd3f914835a16bd4011801dfa0976fedf61bf02', 'pawoo.net', 'limited', 'Hosting media illegal in Germany ');
addInfo('d77ba0c0b39011b7c894510db43047b5b3159a969e2ec887663744ba6924f01d', 'sinblr.com', 'limited', 'untagged nsfw content');
addInfo('2857502859a31520ad5a21bcb31ab9a54ec08205ae129e8d6f6e753626484eaf', '765racing.com', 'suspended', 'Considered being lawless');
addInfo('d464ab2c718d89f9b9ee21ef536b630e392e40736c7dca12423bdb78aea0d365', 'activitypub-troll.cf', 'suspended', 'malicious actor');
addInfo('e7afdc8e99794b60044d2dc69853232fd88bf7767b08d57c06eae1dcdc2cf6d6', 'anim*.****ite', 'suspended', 'shitposting instance, administration seems pro-pedophilia and lolicon-content');
addInfo('87acc08804bcc3b72254fcae7381f2e03a6cb117d2636480bf65125f88b42da6', 'bae.st', 'suspended', 'Unknown');
addInfo('a3da30d2dfb76009289509cb3f35abd0a43b0736f0abf1ddd17c05685902a6fb', 'baraag.net', 'suspended', 'much unmoderated loli content and related');
addInfo('8a6c5f9ea165f8d3d2f73f35bd420f09454829f8cd7f8c250a348c175badc817', 'brands.town', 'suspended', 'spam / copyright violations / impersonation (funny tho)');
addInfo('0be5721be2346e0b892e6cc0db706b6b950a0d215d9d5481e851785571a89067', 'brighteon.social', 'suspended', 'hatespeech, misinformation, shitposting, ...');
addInfo('fc17daf8d2dbc999aa1da044992bff67c4e2f565aabe6bc1f15d74473eff9507', 'childpawn.shop', 'suspended', 'loli/pedophilia, racist content');
addInfo('4861b07e6450e2a5a862124420db543c46fcc7d280c8e0d5e07b2d388ea1e636', 'crypto-group-buy.com', 'suspended', 'spam');
addInfo('a61fbbd27becc4c23ca5307f89703853c3538aff5839e8dab161221939a536de', 'degenerates.fail', 'suspended', 'considered being lawless');
addInfo('66deb7ec370ee6ff869c4fb64855a3dce8624603806502cde81bd70d7b4bff8d', 'detroitriotcity.com', 'suspended', 'trolling, hate speech');
addInfo('d4c09ee9b14ee7c910984859d497c004712a20f20f0eccf337b5fb8cc1123f45', 'eveningzoo.club', 'suspended', 'unmoderated/lawless: much shitposting/spammy content violating multiple instancerules');
addInfo('ced9128fc7e5eb0398245e58610c1c006e01ac879e7cb66c6880d2e43174e89b', 'exited.eu', 'suspended', 'Considered being lawless');
addInfo('d6809fe37cd400946160ffb69fd29ab6d5b92ec5bc30c60d1660b02296ec4da3', 'fedichive.tk', 'suspended', 'Spam');
addInfo('23414c6b236b245c662efa05db8662743261e08cf154237d5190a6ec26887e1c', 'freeatlantis.com', 'suspended', 'fake news / propaganda');
addInfo('7f26b4fd2707a70492f35ba6383d8f42f991474a9072f13e2c50bf5915fb9709', 'freecu*********t.com', 'suspended', 'shitposting instance, bad moderation');
addInfo('55c7e62758bbff9205c11efab25bddf0437423e64fd99c110d76e3479e7ee8f1', 'freefedifollowers.ga', 'suspended', 'Spam / Harmful administration activities');
addInfo('a67a3f85d90881ae32716d0eaf5a348b53096e07ea38a20797d74824074e281b', 'freespeechextremist.com', 'suspended', 'Instance-wide Content Warning');
addInfo('8be74977142a1008ea8c5173c60cb33a1bda7c5ef794b0d38ddef69b5c266b79', 'friendica.eskimo.com', 'suspended', 'admin appears to be openly racist');
addInfo('a32ca19226c88a08be5483053f71ccacae76506b60c9ac14174bbc50d9fc3705', 'gab.ai', 'suspended', 'Considered being lawless');
addInfo('e8bd7afb2125b7ea5e1b885fac2a657d817eec289ed870aa3d1d0acbe6aded8f', 'gab.com', 'suspended', 'Considered being lawless');
addInfo('75e80dd194bc635186cf0b4a07524d7746b4b261cbd5fb15007189e4fccfbbb6', 'gameliberty.club', 'suspended', 'Suspicious or harmful administration activity / considered lawless');
addInfo('69f6d1fc74a4f97f67a6a2c82d322beb423b16266ec4af2ff0a3c097061dfa85', 'ginny.chat', 'suspended', 'Suspicious or harmful administration activity');
addInfo('ce478739d7d3627cbde08e6276b80d459a2bbf842b2698a195684f581ac8defa', 'gitmo.life', 'suspended', 'considered being lawless');
addInfo('56da8b2c7030ff79b9acba7a23fb6750a165a88505e0dcac85478d537d88e90f', 'glindr.org', 'suspended', 'unknown');
addInfo('55ae7fc705dc6b408085ba34c7f0172ffce1fad11c707ca900f49475dad3a352', 'hentai.baby', 'suspended', 'loli');
addInfo('8b92d2bc4447cf5475ec0a688c1894ae5ccc720c034e46c2855ac808909172c9', 'iddqd.social', 'suspended', 'multiple rule violations');
addInfo('bffe6724c620cd252569678f9cdee5a1da51f23ec7d2ce45508ad10f0499d3ff', 'kenfm.de', 'suspended', 'Conspiracy theories, hate speech');
addInfo('83b5c39377a7ddfe05e1b10512a9c3c84f997e1a1bc8b4eb2abc2845755d4c64', 'kitty.town', 'suspended', 'Suspicious or harmful administration activity');
addInfo('8c07b582ccad117d4fa14d4acca0d6977a0a737eb00e0f6a1ddf08228532e708', 'kiwifarms.cc', 'suspended', 'Instance-wide Content Warning');
addInfo('1522dc9020fbf0ce2a1433a49bc9e026b3042b4570707dc61c980d33af128203', 'loli.pizza', 'suspended', 'Not well moderated, allows loli content - even "boosted" by admin');
addInfo('99175a148ba5f37647e0e8e7e797066bcd36797e93eba8c488bb5811289977e4', 'masto.glx-consulting.com', 'suspended', 'Excessive spread of conspiracy myths');
addInfo('7285a20cadbf9bca0510d695df0c45492700cf11b9a1a55f6004149fd2afdea7', 'meld.de', 'suspended', 'Conspiracy instance');
addInfo('89c918c5efd375789869f7068c6cf47389909ff281a514fa4a60d6f17bda3eb2', 'my.dirtyhobby.xyz', 'suspended', 'unmoderated content');
addInfo('a9defb603c0ff2a974c51fcfbf46f19f40f4214f492dbd7e21f0459f283b1902', 'nazi.social', 'suspended', 'unknown');
addInfo('19452ff02670099643197b3fec15c0d43e42a3dbbe83b0fb4d039d5f77d1932e', 'neckbeard.xyz', 'suspended', 'considered lawless: shitposter instance seemingly allowing loli/conspiracy/hatespeech content ');
addInfo('43f46e704409dbeab808c27b5d78ab5164d9bc52a2d06bef7907dca30935ea5e', 'newjack.city', 'suspended', 'Considered being lawless');
addInfo('03862ed4050b1d6c7b914e369284d75f9cffd17288e13d6587dad5ee51599be5', 'noagendasocial.com', 'suspended', 'hatespeech, misinformation, shitposting, ...');
addInfo('95896a6fa94fa220d15314771a5757484f1e531a7a0a8ce6bee5d178a1e9966a', 'nobodyhasthe.biz', 'suspended', 'national socialism, and more');
addInfo('458e6284e52fbebf33c2be2ffef00653fab79f8b4c0ff2da5ce4d0e4653dd925', 'ns.auction', 'suspended', 'Unmoderated racism');
addInfo('843729dbdb7430e3ff2364c5fbb6a40df3fe8ea2bf439adb13a7072b691c257e', 'pl.smuglo.li', 'suspended', 'Considered being lawless');
addInfo('24f316abb4ecb518311996750acba82970a678e00927266e09e51705267836c2', 'poa.st', 'suspended', 'Self-described as shitposting-instance, much racist content');
addInfo('0bdc61adc504242126851f09de2a68f2e6821cc9843e618fd843a5cabf284fea', 'posting.lolicon.rocks', 'suspended', 'multiple rule violations by users and admins (such as symbols of national socialism)');
addInfo('8eeee5a7e282bb5cbcf6e2f6d6db74b2d4e3ca2dbb21e7abfb4188c047e8a861', 'querdenken-711.de', 'suspended', 'dedicated to conspiracy myths');
addInfo('e662672d14b94b33a85de581cb83125a38f266e52e98158c16ae8c82600c9db1', 'radiosocial.org', 'suspended', 'discontinued instance, block to avoid errors');
addInfo('c90dc2eff751603d479d7011e24177a1a3b450a47bb87063d3e295cc33675f85', 'sealion.club', 'suspended', 'Considered being lawless');
addInfo('15e9b52c5fa83bfbe8a8c258bacf9af2c6fc96b7c899bd3ce38e4bbcd760d913', 'search.fedi.app', 'suspended', 'unknown');
addInfo('a456580c35ff79445118613dc23cabcc61f4f43ba6d777faaaa667d3de7262c4', 'shitposter.club', 'suspended', 'Considered being lawless');
addInfo('98828c9a5c00114ac673ea4e7c1979599af51ce8ead9d9689a862c1a3e01bef3', 'sleepy.cafe', 'suspended', 'shitposting / harassment / nazistuff');
addInfo('b86a99c713273468fcdc199bc6b11902dadd1e77960309c606817b00455473ed', 'sneed.social', 'suspended', 'shitposting/nazism/hatespeech instance');
addInfo('90ef730c962b6bbfb855bc673ec7af634bcdc3bf33b5830709a481f75a427f92', 'social.ancreport.com', 'suspended', 'spam and loli content, overall content violates multiple rules');
addInfo('8c8275efb10967a4b75e55e22fa97be182e47a0a0887d2e478a05b905291f8c4', 'social.hatthieves.es', 'suspended', 'Suspicious or harmful administration activity / considered lawless');
addInfo('947af47d7e18a94cd7b561e4ee482572d0e1aa899b2aae0d39646b90f91079ba', 'socnet.softgirl.online', 'suspended', 'spam');
addInfo('02eeb2d1ddbf3ed33ba965a3ca6c57982afa149dd7e27f50ec47e2e184a09191', 'solagg.com', 'suspended', 'spam, possibly harmful activities, will re-review');
addInfo('0c6b4fdf03346b1449ed0a697fe2e4a54a04706ff21e09593e1e4ffc0fb02d22', 'tcode.kenfm.de', 'suspended', 'hate speech, racism, conspiracy theories');
addInfo('4bfe1e125963fa3f9af140bb715a1de94d5d38a6e96cdf45f42eb284be1ca371', 'truthsocial.com', 'suspended', 'hate speech, racism, conspiracy theories');
addInfo('d5420e63098be0fd9747a8d312534bedd63327ec918691df4ddf6e3d01664805', 'twitter.1d4.us', 'suspended', 'spam');
addInfo('f2b2f6302c7d4204817a15a4111516493c18c567249af5c3642b1b85352fab1e', 'varishangout.net', 'suspended', 'loli/weapons/shitpost');
addInfo('793c2d609d9705168d06554967add315acba674b8b3f5fbedcea86881da7ba6f', 'youjo.love', 'suspended', 'unknown');

