// If you normally use a proxy, replace "DIRECT" below with
// "PROXY MACHINE:PORT"
// where MACHINE is the IP address or host name of your proxy
// server and PORT is the port number of your proxy 
// Define the blackhole proxy for blocked adware and trackware

var normal = "DIRECT";
var proxy = "DIRECT";                  // e.g. 127.0.0.1:3128
// var blackhole_ip_port = "127.0.0.1:8119";  // ngnix-hosted blackhole
// var blackhole_ip_port = "8.8.8.8:53";      // GOOG DNS blackhole; do not use: no longer works with iOS 11—causes long waits on some sites
var blackhole_ip_port = "127.0.0.1:8119";    // on iOS a working blackhole requires return code 200;
// e.g. use the adblock2privoxy nginx server as a blackhole
var blackhole = "PROXY " + blackhole_ip_port;

// The hostnames must be consistent with EasyList format.
// These special RegExp characters will be escaped below: [.?+@]
// This EasyList wildcard will be transformed to an efficient RegExp: *
// 
// EasyList format references:
// https://adblockplus.org/filters
// https://adblockplus.org/filter-cheatsheet

// Create object hashes or compile efficient NFA's from all filters
// Various alternate filtering and regex approaches were timed using node and at jsperf.com
// 
// Strategies to convert EasyList rules to Javascript tests:
// 
// In general:
// 1. Preference for performance over 1:1 EasyList functionality
// 2. Limit number of rules to ~O(10k) to avoid computational burden on mobile devices
// 3. Exact matches: use Object hashing (very fast); use efficient NFA RegExp's for all else
// 4. Divide and conquer specific cases to avoid large RegExp's
// 5. Based on testing code performance on an iPhone: mobile Safari, Chrome with System Activity Monitor.app
// 6. Backstop these proxy.pac rules with Privoxy rules and a browser plugin
// 
// scheme://host/path?query ; FindProxyForURL(url, host) has full url and host strings
// 
// EasyList rules:
// 
// || domain anchor
// 
// ||host is exact e.g. ||a.b^ ? then hasOwnProperty(hash,host)
// ||host is wildcard e.g. ||a.* ? then RegExp.test(host)
// 
// ||host/path is exact e.g. ||a.b/c? ? then hasOwnProperty(hash,url_path_noquery) [strip ?'s]
// ||host/path is wildcard e.g. ||a.*/c? ? then RegExp.test(url_path_noquery) [strip ?'s]
// 
// ||host/path?query is exact e.g. ||a.b/c?d= ? assume none [handle small number within RegExp's]
// ||host/path?query is wildcard e.g. ||a.*/c?d= ? then RegExp.test(url)
// 
// url parts e.g. a.b^c&d|
// 
// All cases RegExp.test(url)
// Except: |http://a.b. Treat these as domain anchors after stripping the scheme
// 
// regex e.g. /r/
// 
// All cases RegExp.test(url)
// 
// @@ exceptions
// 
// Flag as "good" versus "bad" default
// 
// Variable name conventions (example that defines the rule):
// 
// bad_da_host_exact == bad domain anchor with host/path type, exact matching with Object hash
// bad_da_host_regex == bad domain anchor with host/path type, RegExp matching
// 
// 71 rules:
var good_da_host_JSON = { "apple.com": null,
"icloud.com": null,
"apple-dns.net": null,
"swcdn.apple.com": null,
"init.itunes.apple.com": null,
"init-cdn.itunes-apple.com.akadns.net": null,
"itunes.apple.com.edgekey.net": null,
"setup.icloud.com": null,
"p32-escrowproxy.icloud.com": null,
"p32-escrowproxy.fe.apple-dns.net": null,
"keyvalueservice.icloud.com": null,
"keyvalueservice.fe.apple-dns.net": null,
"p32-bookmarks.icloud.com": null,
"p32-bookmarks.fe.apple-dns.net": null,
"p32-ckdatabase.icloud.com": null,
"p32-ckdatabase.fe.apple-dns.net": null,
"configuration.apple.com": null,
"configuration.apple.com.edgekey.net": null,
"mesu-cdn.apple.com.akadns.net": null,
"mesu.g.aaplimg.com": null,
"gspe1-ssl.ls.apple.com": null,
"gspe1-ssl.ls.apple.com.edgekey.net": null,
"api-glb-bos.smoot.apple.com": null,
"query.ess.apple.com": null,
"query-geo.ess-apple.com.akadns.net": null,
"query.ess-apple.com.akadns.net": null,
"setup.fe.apple-dns.net": null,
"gsa.apple.com": null,
"gsa.apple.com.akadns.net": null,
"icloud-content.com": null,
"usbos-edge.icloud-content.com": null,
"usbos.ce.apple-dns.net": null,
"lcdn-locator.apple.com": null,
"lcdn-locator.apple.com.akadns.net": null,
"lcdn-locator-usuqo.apple.com.akadns.net": null,
"cl1.apple.com": null,
"cl2.apple.com": null,
"cl3.apple.com": null,
"cl4.apple.com": null,
"cl5.apple.com": null,
"cl1-cdn.origin-apple.com.akadns.net": null,
"cl2-cdn.origin-apple.com.akadns.net": null,
"cl3-cdn.origin-apple.com.akadns.net": null,
"cl4-cdn.origin-apple.com.akadns.net": null,
"cl5-cdn.origin-apple.com.akadns.net": null,
"cl1.apple.com.edgekey.net": null,
"cl2.apple.com.edgekey.net": null,
"cl3.apple.com.edgekey.net": null,
"cl4.apple.com.edgekey.net": null,
"cl5.apple.com.edgekey.net": null,
"xp.apple.com": null,
"xp.itunes-apple.com.akadns.net": null,
"mt-ingestion-service-pv.itunes.apple.com": null,
"p32-sharedstreams.icloud.com": null,
"p32-sharedstreams.fe.apple-dns.net": null,
"p32-fmip.icloud.com": null,
"p32-fmip.fe.apple-dns.net": null,
"gsp-ssl.ls.apple.com": null,
"gsp-ssl.ls-apple.com.akadns.net": null,
"gsp-ssl.ls2-apple.com.akadns.net": null,
"gspe35-ssl.ls.apple.com": null,
"gspe35-ssl.ls-apple.com.akadns.net": null,
"gspe35-ssl.ls.apple.com.edgekey.net": null,
"gsp64-ssl.ls.apple.com": null,
"gsp64-ssl.ls-apple.com.akadns.net": null,
"mt-ingestion-service-st11.itunes.apple.com": null,
"mt-ingestion-service-st11.itunes-apple.com.akadns.net": null,
"microsoft.com": null,
"mozilla.com": null,
"mozilla.org": null };
var good_da_host_exact_flag = 70 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_da_host_RegExp = /^$/;
var good_da_host_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules

// 0 rules:
var good_da_hostpath_JSON = {  };
var good_da_hostpath_exact_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_da_hostpath_RegExp = /^$/;
var good_da_hostpath_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_da_RegExp = /^$/;
var good_da_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules

// 39 rules:
var good_da_host_exceptions_JSON = { "iad.apple.com": null,
"iadsdk.apple.com": null,
"iadsdk.apple.com.edgekey.net": null,
"bingads.microsoft.com": null,
"azure.bingads.trafficmanager.net": null,
"choice.microsoft.com": null,
"choice.microsoft.com.nsatc.net": null,
"corpext.msitadfs.glbdns2.microsoft.com": null,
"corp.sts.microsoft.com": null,
"df.telemetry.microsoft.com": null,
"diagnostics.support.microsoft.com": null,
"feedback.search.microsoft.com": null,
"i1.services.social.microsoft.com": null,
"i1.services.social.microsoft.com.nsatc.net": null,
"redir.metaservices.microsoft.com": null,
"reports.wes.df.telemetry.microsoft.com": null,
"services.wes.df.telemetry.microsoft.com": null,
"settings-sandbox.data.microsoft.com": null,
"settings-win.data.microsoft.com": null,
"sqm.df.telemetry.microsoft.com": null,
"sqm.telemetry.microsoft.com": null,
"sqm.telemetry.microsoft.com.nsatc.net": null,
"statsfe1.ws.microsoft.com": null,
"statsfe2.update.microsoft.com.akadns.net": null,
"statsfe2.ws.microsoft.com": null,
"survey.watson.microsoft.com": null,
"telecommand.telemetry.microsoft.com": null,
"telecommand.telemetry.microsoft.com.nsatc.net": null,
"telemetry.urs.microsoft.com": null,
"vortex.data.microsoft.com": null,
"vortex-sandbox.data.microsoft.com": null,
"vortex-win.data.microsoft.com": null,
"cy2.vortex.data.microsoft.com.akadns.net": null,
"watson.microsoft.com": null,
"watson.ppe.telemetry.microsoft.comwatson.telemetry.microsoft.com": null,
"watson.telemetry.microsoft.com.nsatc.net": null,
"wes.df.telemetry.microsoft.com": null,
"win10.ipv6.microsoft.com": null,
"www.bingads.microsoft.com": null };
var good_da_host_exceptions_exact_flag = 39 > 0 ? true : false;  // test for non-zero number of rules

// 1326 rules:
var bad_da_host_JSON = { "mesu.apple.com": null,
"ocsp.apple.com": null,
"1126bet.com": null,
"11bet.com": null,
"11bet.net": null,
"11bet.win": null,
"123b.com": null,
"12b99.com": null,
"179bet.net": null,
"19534.redirect.appmetrica.yandex.com": null,
"1xbetvn.com": null,
"3.redirect.appmetrica.yandex.com": null,
"30488.redirect.appmetrica.yandex.com": null,
"388bet.top": null,
"388bet.us": null,
"388bet.vin": null,
"388bet.vip": null,
"3kingclub.com": null,
"4.afs.googleadservices.com": null,
"4.redirect.appmetrica.yandex.com": null,
"50soc.com": null,
"5123b.com": null,
"520xiaojin.com": null,
"5734a40f2d.vws.vegacdn.vn": null,
"68rich.com": null,
"68rich.org": null,
"703531862.vws.vegacdn.vn": null,
"789.club": null,
"789.fun": null,
"789.moi": null,
"789club.biz": null,
"789club.org": null,
"79lucky.com": null,
"888b.com": null,
"888b.in": null,
"88viet.com": null,
"88vwin.com": null,
"8live.com": null,
"8live.fun": null,
"8live.net": null,
"8live.top": null,
"8live.vip": null,
"8livevn.com": null,
"a.applovin.com": null,
"a.mouseflow.com": null,
"a.teads.tv": null,
"a.vtvdigital.vn": null,
"aa88.in": null,
"aan.amazon.com": null,
"aax-fe-sin.amazon-adsystem.com": null,
"abrts.pro": null,
"access.adblox.net": null,
"acdn.adnxs.com": null,
"ad-admin.vnay.vn": null,
"ad-apac.doubleclick.net": null,
"ad-creatives-public.commondatastorage.googleapis.com": null,
"ad-emea.doubleclick.net": null,
"ad-g.doubleclick.net": null,
"ad-log.dable.io": null,
"ad.24h.com.vn": null,
"ad.8live.com": null,
"ad.adsrvr.org": null,
"ad.afy11.net": null,
"ad.chieuhoa.com": null,
"ad.daum.net": null,
"ad.eva.vn": null,
"ad.happynest.vn": null,
"ad.icheck.com.vn": null,
"ad.lapa.pub": null,
"ad.mo.doubleclick.net": null,
"ad.mwork.vn": null,
"ad.org.vn": null,
"ad.phunuxuavanay.vn": null,
"ad.qtcs.com.vn": null,
"ad.samsungadhub.com": null,
"ad.samsungads.com": null,
"ad.sunflower.vn": null,
"ad.vkool.net": null,
"ad.xiaomi.com": null,
"ad.zing.vn": null,
"ad2.nend.net": null,
"ad360.vn": null,
"adadmin.headlines.pw": null,
"adapi.tuyensinh247.com": null,
"adasiaholdings.com": null,
"adc.quantrimang.com": null,
"adchoice.com": null,
"adclient.vietnamnetjsc.vn": null,
"adconnect.vn": null,
"addlog.thuvienphapluat.vn": null,
"addtop.trangvangvietnam.com": null,
"ade.googlesyndication.com": null,
"adflex.vn": null,
"adfly.vn": null,
"adfox.vn": null,
"adfox.yandex.ru": null,
"adi.tuiiu.com": null,
"adjusts.info": null,
"adm.phunusuckhoe.vn": null,
"adm.phunuvagiadinh.vn": null,
"adi.admicro.vn": null,
"admicro1.vcmedia.vn": null,
"admin.appnext.com": null,
"admin.phunusuckhoe.vn": null,
"admin.sothuchi.vn": null,
"admin.voh.com.vn": null,
"admobclick.com": null,
"adn.insight.ucweb.com": null,
"adnet.vn": null,
"adnetwork.vn": null,
"adpostback.headlines.pw": null,
"adrealclick.com": null,
"adrta.com": null,
"ads-api.playfun.vn": null,
"ads-backend.nhadatmoi.net": null,
"ads-bid.l.doubleclick.net": null,
"ads-brand-postback.unityads.unity3d.com": null,
"ads-cdn.fptplay.net": null,
"ads-d.viber.com": null,
"ads-game-configuration-master.ads.prd.ie.internal.unity3d.com": null,
"ads-target.coccoc.com": null,
"ads-thanhnien-vn.cdn.ampproject.org": null,
"ads-twitter.com": null,
"ads.1thegioi.vn": null,
"ads.568play.vn": null,
"ads.adaptv.advertising.com": null,
"ads.altema.jp": null,
"ads.as.criteo.com": null,
"ads.autonet.com.vn": null,
"ads.avocet.io": null,
"ads.aws.viber.com": null,
"ads.baoangiang.com.vn": null,
"ads.baobinhduong.vn": null,
"ads.baocantho.com.vn": null,
"ads.baodatviet.vn": null,
"ads.baotainguyenmoitruong.vn": null,
"ads.bkitsoftware.com": null,
"ads.businessstyle.vn": null,
"ads.careerbuilder.vn": null,
"ads.carmudi.vn": null,
"ads.conlatatca.vn": null,
"ads.contextweb.com": null,
"ads.exdynsrv.com": null,
"ads.exosrv.com": null,
"ads.fptplay.net.vn": null,
"ads.glispa.com": null,
"ads.google.com": null,
"ads.gosu.vn": null,
"ads.heyzap.com": null,
"ads.home.vn": null,
"ads.homedy.com": null,
"ads.ictnews.vn": null,
"ads.itsgroup.vn": null,
"ads.khoahocdoisong.vn": null,
"ads.kiemsat.vn": null,
"ads.lamchame.vn": null,
"ads.laodongbinhduong.org.vn": null,
"ads.laodongnghean.vn": null,
"ads.linkedin.com": null,
"ads.marry.vn": null,
"ads.netlinkad.vn": null,
"ads.nghenhinvietnam.vn": null,
"ads.nhadatmoi.net": null,
"ads.pcccdongduong.vn": null,
"ads.phunuonline.com.vn": null,
"ads.phunusuckhoe.vn": null,
"ads.phunuvagiadinh.vn": null,
"ads.pinterest.com": null,
"ads.platform.zalo.me": null,
"ads.reddit.com": null,
"ads.rekmob.com": null,
"ads.songmoi.vn": null,
"ads.stickyadstv.com": null,
"ads.suckhoegiadinh.com.vn": null,
"ads.thanhnien.vn": null,
"ads.thegioitiepthi.vn": null,
"ads.thesaigontimes.vn": null,
"ads.thitruongtaichinhtiente.vn": null,
"ads.tiki.vn": null,
"ads.tiktok.com": null,
"ads.vietbao.vn": null,
"ads.vishare.vn": null,
"ads.vkool.info": null,
"ads.vlr.vn": null,
"ads.vovlive.vn": null,
"ads.xedoisong.vn": null,
"ads.xemphimso.com": null,
"ads.yap.yahoo.com": null,
"ads.youtube.com": null,
"ads.zalo.me": null,
"ads.zaloapp.com": null,
"ads.zdn.vn": null,
"ads1.careerbuilder.vn": null,
"ads2.servebom.com": null,
"adsbanner.game.zing.vn": null,
"adsdk.yandex.ru": null,
"adserver.lag.vn": null,
"adserver.luzu.vn": null,
"adserver.muaban.net": null,
"adserver.trangphim.net": null,
"adserver.unityads.unity3d.com": null,
"adserver.yahoo.com": null,
"adservetx.media.net": null,
"adsfs.oppomobile.com": null,
"adsgo.nhipcaudautu.vn": null,
"adskeeper.com": null,
"adsnetonline.work": null,
"adsota.com": null,
"adsparc.com": null,
"adspecs.yahoo.com": null,
"adsplay.net": null,
"adsplay.xyz": null,
"adsplus.vn": null,
"api2.appsflyer.com": null,
"adsv2.autodaily.vn": null,
"adsweb.vn": null,
"adt.com.vn": null,
"adtima-common.zadn.vn": null,
"adtima-common.zascdn.me": null,
"adtima-media-td.zadn.vn": null,
"adtima-media.zadn.vn": null,
"adtima-media.zascdn.me": null,
"adtima-static-td.zadn.vn": null,
"adtima-static.zadn.vn": null,
"adtima-static.zascdn.me": null,
"adtima-video.zadn.vn": null,
"adtima-video.zascdn.me": null,
"adtima.net.vn": null,
"adtima.org": null,
"adtima.vn": null,
"adtimaserver.vn": null,
"adtrack.chartboosts.com": null,
"adv.anhsangvacuocsong.vn": null,
"adv.autosurf.vn": null,
"adv.baotintuc.vn": null,
"adv.baovemoitruong.org.vn": null,
"adv.klick.vn": null,
"adv.thuvienphapluat.vn": null,
"adv.vnnshop.vn": null,
"adver.24h.com.vn": null,
"advert-admin.vnay.vn": null,
"advertisement-nhatanh.com": null,
"advertising.yahoo.com": null,
"advserver.cgv.vn": null,
"advzone.ioe.vn": null,
"adx.ads.oppomobile.com": null,
"adx.baolongan.vn": null,
"adx.chinmedia.vn": null,
"adx.edutimes.com.vn": null,
"adx.g.doubleclick.net": null,
"adx.golfnews.vn": null,
"adx.hongtinnhanh.com": null,
"adx.kul.vn": null,
"adx.phunuadong.vn": null,
"adx.vn": null,
"adx.xemvtv.net": null,
"adx.xtv.vn": null,
"ae888.com": null,
"affiliate.chiaki.vn": null,
"ai.thanhnien.vn": null,
"ailamtrieuphu.com": null,
"ak9.6895588.com": null,
"alexajstrack.com": null,
"alivar.com.vn": null,
"alivar.vn": null,
"alog.umeng.com": null,
"amazon-adsystem.com": null,
"ambient-platform.com": null,
"ambientdsp.com": null,
"amobi.vn": null,
"amprtc.media.net": null,
"an.dongphim.net": null,
"an.motphim.net": null,
"an.xemvtv.net": null,
"an.yandex.ru": null,
"analysis2.chartboosts.com": null,
"pagead2.googlesyndication.com": null,
"analytics.admon.com.vn": null,
"adx.admicro.vn": null,
"static-cmsads.admicro.vn": null,
"analytics.diamondstarfinancial.com.vn": null,
"analytics.easyvideo.vn": null,
"analytics.explus.vn": null,
"analytics.facebook.com": null,
"analytics.hub-js.com": null,
"analytics.mfocus.vn": null,
"analytics.mobile.yandex.net": null,
"analytics.moneycat.vn": null,
"u3y8v8u3.ackcdn.net": null,
"analytics.oneplus.cn": null,
"analytics.ad.daum.net": null,
"analytics-ad-eyu9u2md.kgslb.com": null,
"securepubads.g.doubleclick.net": null,
"analytics.rayjump.com": null,
"analytics.rever.vn": null,
"media1.admicro.vn": null,
"ads.api.vungle.com": null,
"analytics.tiktok.com": null,
"sg.megaad.nz": null,
"adclick.g.doubleclick.net": null,
"anthill.vn": null,
"ants.vn": null,
"anymind360-com.cdn.ampproject.org": null,
"ap.lijit.com": null,
"inmobi.net": null,
"api.ad.xiaomi.com": null,
"api.adserver.vrizead.com": null,
"api.adsnative.com": null,
"api.adtimaserver.vn": null,
"api.appodeal.com": null,
"api.appodealx.com": null,
"api.apptap.com": null,
"api.branch.io": null,
"api.getrocketapp.io": null,
"api.mgid.com": null,
"api.nas.nct.vn": null,
"api.ozui.vn": null,
"api.uca.cloud.unity3d.com": null,
"apia.headlines.pw": null,
"apinas.nct.vn": null,
"apireporting.revmobads.com": null,
"apiv2.tiin.vn": null,
"apl.headlines.pw": null,
"app.hstatic.net": null,
"app.sbz.workers.dev": null,
"appgasstation.com": null,
"banner.appsflyer.com": null,
"appnext-722476687.us-east-1.elb.amazonaws.com": null,
"appservice-dot-mystic-tempo-847.appspot.com": null,
"as.gamevui.com": null,
"asset.adserver.vrizead.com": null,
"assets.applovin.com": null,
"assoc-amazon.com": null,
"ata-ads.realmemobile.com": null,
"atdnetwork.com": null,
"atspace.tv": null,
"auction.unityads.unity3d.com": null,
"autoads.asia": null,
"avd.innity.net": null,
"avoadsservices.com": null,
"aw8vn2.com": null,
"b.scorecardresearch.com": null,
"b1sync.zemanta.com": null,
"b29qc.win": null,
"b52.win": null,
"bam.nr-data.net": null,
"banhtv.org": null,
"bank.reklamstore.com": null,
"banner.5giay.vn": null,
"banner.etargeting.mobifone.vn": null,
"banner.thadaco.vn": null,
"banner.trangvangvietnam.com": null,
"banner.vietnamfinance.vn": null,
"banners-gallery.coccoc.com": null,
"banners-slb.mobile.yandex.net": null,
"banners.mobile.yandex.net": null,
"baogia.vads.vn": null,
"bats.video.yahoo.com": null,
"bdapi-in-ads.realmemobile.com": null,
"bdapi.ads.oppomobile.com": null,
"beacon-apac-hkg1.rubiconproject.com": null,
"beacon-eu2.rubiconproject.com": null,
"beacon-nf.rubiconproject.com": null,
"beacon.krxd.net": null,
"best.hot-blogs.info": null,
"bestcacuoc8.com": null,
"beta.mybestmv.com": null,
"betvietnam.info": null,
"betvisa.com": null,
"bevo.eu-west1.getpolymorph.com": null,
"bid.adview.cn": null,
"bidder.criteo.com": null,
"bidgear-syndication.com": null,
"big88.one": null,
"bigdata.ssp.samsung.com": null,
"blogstatistics.sapoapps.vn": null,
"bloodleian.club": null,
"blueadss.com": null,
"a.blueserving.com": null,
"ssp.blueserving.com": null,
"b.blueserving.com": null,
"bong88net.com": null,
"bong99.com": null,
"bong99.fun": null,
"bong99.live": null,
"bong99.vip": null,
"bongacams.com": null,
"bongdadem.net": null,
"boom66.com": null,
"boudja.com": null,
"br.adspecs.yahoo.com": null,
"adi.vcmedia.vn": null,
"bristlyapace.com": null,
"browser.sentry-cdn.com": null,
"warden.arc.io": null,
"bs-meta.yandex.ru": null,
"bs.yandex.ru": null,
"btrack.homedy.com": null,
"business.samsungusa.com": null,
"bvadimgs.scdn7.secure.raxcdn.com": null,
"bwingmkt8.com": null,
"bwstatistics.bizwebapps.vn": null,
"bwstatistics.sapoapps.vn": null,
"byonlym.com": null,
"c.bebi.com": null,
"c.rigelink.com": null,
"c3.hadarone.com": null,
"c5.hadarone.com": null,
"cacuoc247.com": null,
"cacuoc79.com": null,
"admatic.admicro.vn": null,
"campxanh.info": null,
"casino888vn.com": null,
"cat.hk.as.criteo.com": null,
"cbsi.demdex.net": null,
"cbsinteractive.hb.omtrdc.net": null,
"cdfv.pro": null,
"cdn-adn-https.rayjump.com": null,
"cdn-ads.thesaigontimes.vn": null,
"cdn-bongdadem-net.cdn.ampproject.org": null,
"cdn-qc.coccoc.com": null,
"cdn.ad4game.com": null,
"cdn.adtrue.com": null,
"cdn.advertserve.com": null,
"cdn.ambientplatform.vn": null,
"cdn.appnext.com": null,
"cdn.appsflyer.com": null,
"cdn.comedia.coccoc.com": null,
"cdn.doke.app": null,
"cdn.fastclick.net": null,
"cdn.gdns.revopush.com": null,
"cdn.innity.net": null,
"cdn.intergi.com": null,
"cdn.krxd.net": null,
"cdn.liftoff.io": null,
"cdn.push.house": null,
"cdn.radiantmediatechs.com": null,
"cdn.stickyadstv.com": null,
"cdn.taboola.com": null,
"cdn.tekoapis.com": null,
"cdn.viglink.com": null,
"cdn2.inner-active.mobi": null,
"cdn3.cpmstar.com": null,
"adrevenue.appsflyer.com": null,
"stripchat.com": null,
"cdnstoremedia.com": null,
"cdp.asia": null,
"ce.lijit.com": null,
"celerantatters.com": null,
"tracker.arc.io": null,
"cettiarl.com": null,
"cheap-ads.net": null,
"chin-adnetwork.com": null,
"ck.ads.oppomobile.com": null,
"clck.yandex.ru": null,
"clevernet.vn": null,
"click-ads.saoteen.net": null,
"click.gowadogo.com": null,
"click.oneplus.cn": null,
"click.oneplus.com": null,
"click.vieon.vn": null,
"clickbuy.bz": null,
"clicker.chiaki.vn": null,
"tkr.arc.io": null,
"clix.vn": null,
"clk.taptica.com": null,
"clksite.com": null,
"go.stripchat.com": null,
"cms.analytics.yahoo.com": null,
"cnzz.mmstat.com": null,
"codon.vn": null,
"collect.ovp.vn": null,
"config.samsungads.com": null,
"config.uca.cloud.unity3d.com": null,
"config.unityads.unity3d.com": null,
"connect.tapjoy.com": null,
"consumer.krxd.net": null,
"contextual.media.net": null,
"copicvarianuty.info": null,
"core.vnecdn.com": null,
"counter.24h.com.vn": null,
"counter.ntdvn.com": null,
"cpx.vnecdn.com": null,
"criteo.com": null,
"criteo.net": null,
"crm.bizfly.vn": null,
"crmbizfly.todo.vn": null,
"croissed.info": null,
"propeller-tracking.com": null,
"csm.as.criteo.net": null,
"csmads.gameclick.vn": null,
"ct.pinterest.com": null,
"cvision.media.net": null,
"d.agkn.com": null,
"connect-metrics-collector.s-onetag.com": null,
"d5.hadarone.com": null,
"dart.l.doubleclick.net": null,
"data.ads.oppomobile.com": null,
"data.mistat.intl.xiaomi.com": null,
"data.mistat.xiaomi.com": null,
"datcuoc247.com": null,
"de.tynt.com": null,
"de01.rayjump.com": null,
"debet.com": null,
"decide.mixpanel.com": null,
"delecpuzz.com": null,
"deliver.rossoad.com": null,
"delivery.adnetwork.vn": null,
"delivery.lavanetwork.net": null,
"delivery.m.ambientplatform.vn": null,
"delivery.senvangvn.com": null,
"delivery.vtc.vn": null,
"delivery.vtcnew.com.vn": null,
"deltago.com": null,
"demannewcure.site": null,
"demo.klick.vn": null,
"demopage.me": null,
"deqik.com": null,
"detect.rayjump.com": null,
"dfchoingay.com": null,
"dmp.mgid.com": null,
"donglogs.com": null,
"doubleclick.com": null,
"doubleclick.net": null,
"dpm.demdex.net": null,
"drakeesh.com": null,
"dt.adsafeprotected.com": null,
"dt.vnecdn.com": null,
"dtscout.rtb.adx1.com": null,
"duclick.baidu.com": null,
"dzc-metrics.mzstatic.com": null,
"e.crashlytics.com": null,
"e.dlx.addthis.com": null,
"elink.nhanlucnganhluat.vn": null,
"eqx-tmk-geoloc.smartadserver.com": null,
"eurofun88.com": null,
"eus.rubiconproject.com": null,
"eva-ad.24hstatic.com": null,
"event.allnews.uodoo.com": null,
"event.headlines.pw": null,
"event.vntoday.news": null,
"api.appsflyer.com": null,
"events.redditmedia.com": null,
"exchange.superfastmediation.com": null,
"tsyndicate.com": null,
"lg1.logging.admicro.vn": null,
"ezimar.com": null,
"fa.fpt.shop": null,
"fa88.win": null,
"fabet.com": null,
"fabet.me": null,
"fabet.vip": null,
"fabet88.net": null,
"fabetvn.com": null,
"facebookz.co": null,
"fast.forbes.com": null,
"fastlane.rubiconproject.com": null,
"fb88.com": null,
"fb88.link": null,
"fb88club.com": null,
"fb88cup.com": null,
"fb88en.com": null,
"fb88go.com": null,
"fb88live.com": null,
"fb88max.com": null,
"fb88sports.com": null,
"fb88viet.com": null,
"fbuser.ovp.vn": null,
"fcb8.com": null,
"fcb8.fun": null,
"fcb8.vip": null,
"fcb88.com": null,
"fcb88d.com": null,
"fcmatch.google.com": null,
"ff.imacdn.com": null,
"file-subiz.com": null,
"financial-agent.headlines.pw": null,
"ctrack.trafficjunky.net": null,
"five88.biz": null,
"five88.com": null,
"five88.me": null,
"five88.net": null,
"fivevn.net": null,
"flygame.io": null,
"fm.flashtalking.com": null,
"follow.vnay.vn": null,
"forcedolphin.com": null,
"fptad.com": null,
"fun1118.com": null,
"g.eclick.vn": null,
"g1.ads.oppomobile.com": null,
"gafin.vn": null,
"game-static.hotngay.vn": null,
"gamebai.club": null,
"gammaplatform.com": null,
"gammassp.com": null,
"gcloud.download.igamecj.com": null,
"gdwbetvn888.com": null,
"gdwviet.com": null,
"genmonet.com": null,
"geo.query.yahoo.com": null,
"geo.yahoo.com": null,
"ghimc.vn": null,
"gi888.cc": null,
"global.adserver.yahoo.com": null,
"global.appnext.com": null,
"global.ymtracking.com": null,
"globalapi.ad.xiaomi.com": null,
"go.bebi.com": null,
"go.vnecdn.com": null,
"go88.club": null,
"go88.com": null,
"go88vn.vip": null,
"goal123.com": null,
"goal68.net": null,
"goal68.top": null,
"goal86.top": null,
"ads30.adcolony.com": null,
"google-shopping.sapoapps.vn": null,
"googleads4.g.doubleclick.net": null,
"googlecm.hit.gemius.pl": null,
"googleshopping.sapoapps.vn": null,
"gotohouse1.club": null,
"grade.market.yandex.ru": null,
"gstaticadssl.l.google.com": null,
"gtmjs.com": null,
"gum.criteo.com": null,
"h3bet.com": null,
"main.exoclick.com": null,
"happynb.com": null,
"haraads.com": null,
"harafunnel.com": null,
"haraloyalty.com": null,
"haravan.com": null,
"hashearog.com": null,
"hb.nexage.com": null,
"hexapinow.xyz": null,
"hit.123c.vn": null,
"hkspeed.igamecj.com": null,
"hotjar.com": null,
"hotlive8.vip": null,
"hotngay.vn": null,
"html5.adsrvr.org": null,
"i2ad.jp": null,
"iad.appboy.com": null,
"ibet889.com": null,
"ic.tynt.com": null,
"id.rlcdn.com": null,
"ig-us-notice.igamecj.com": null,
"imad24.com": null,
"image2.vnay.vn": null,
"images.babyboomboomads.com": null,
"images.dable.io": null,
"img.applovin.com": null,
"img.mobusi.com": null,
"img.revcontent.com": null,
"img.vietnamnetad.vn": null,
"imgcdnbet.com": null,
"imgg-cdn.adskeeper.co.uk": null,
"imgg-cdn.steepto.com": null,
"imgg.mgid.com": null,
"imggprx.mgid.com": null,
"impression-europe.liftoff.io": null,
"income88.com": null,
"init.supersonicads.com": null,
"interactive.tinnhanhchungkhoan.vn": null,
"interwinvn.com": null,
"inv-nets.admixer.net": null,
"invite.baomoi.com": null,
"irduwhojas.ga": null,
"islandmob.com": null,
"itim.vn": null,
"jbo064.com": null,
"jboviet.com": null,
"jbovietnam.com": null,
"jbovn.com": null,
"js-agent.newrelic.com": null,
"js.ad-stir.com": null,
"js.agkn.com": null,
"jsc.mgid.com": null,
"jslog.krxd.net": null,
"youradexchange.com": null,
"juicyads.com": null,
"k8dl08.cc": null,
"k8sport.com": null,
"k8vina17.com": null,
"k8vn03.com": null,
"kabbmedia.com": null,
"kaurroot.com": null,
"keotot.net": null,
"ketquaxosotoancau.org": null,
"kiks.yandex.ru": null,
"kingbet86.info": null,
"klick.vn": null,
"krping.igamecj.com": null,
"kv-analytics.kiotviet.vn": null,
"la.vietid.net": null,
"landingpagelagi.vn": null,
"larpollicwilli.club": null,
"latam.adspecs.yahoo.com": null,
"lavanetwork.net": null,
"leguinge.info": null,
"letou8868.com": null,
"lg.lotus.vn": null,
"lib1.biz": null,
"live.vnpgroup.net": null,
"lixi88.info": null,
"lixi888.online": null,
"lmi.demdex.net": null,
"load77.exelator.com": null,
"loadeu.exelator.com": null,
"lobby.igamecj.com": null,
"loc88.fun": null,
"loc89.fun": null,
"loc89.vip": null,
"localgirldating.com": null,
"lode555.com": null,
"lode88.vip": null,
"adi.vcmedia.vn": null,
"logging.admicro.vn": null,
"log.fc.yahoo.com": null,
"s4.histats.com": null,
"i.bongacash.com.large.rncdn7.com": null,
"bongacams.com": null,
"ads.exoclick.com": null,
"log.vietnamnetad.vn": null,
"log4x.nixcdn.com": null,
"logapi.misa.com.vn": null,
"logbak.hicloud.com": null,
"logen.vietnamplus.vn": null,
"logg4u.cnnd.vn": null,
"logger.vsmarty.vn": null,
"logs.supersonic.com": null,
"cometmaster.com": null,
"logscafef.channelvn.net": null,
"logservice.hicloud.com": null,
"logservice1.hicloud.com": null,
"c.adskeeper.co.uk": null,
"lottery.vntoday.news": null,
"lucklayed.info": null,
"lucky88.com": null,
"lucky88.live": null,
"lucky88.net": null,
"lucky88.win": null,
"lux39.club": null,
"m.doubleclick.net": null,
"m.five88.net": null,
"m.yap.yahoo.com": null,
"m883d.com": null,
"m88cvf.com": null,
"m88my.com": null,
"m88vina.com": null,
"m8winvip.com": null,
"macau.club": null,
"macauclub.fun": null,
"mads.amazon-adsystem.com": null,
"makemyvids.com": null,
"mangoads.vn": null,
"manifest.googlevideo.com": null,
"mansion66.com": null,
"marketing.hub-js.com": null,
"marketingsolutions.yahoo.com": null,
"match.adsrvr.org": null,
"match.deepintent.com": null,
"matchid.adfox.yandex.ru": null,
"may88.club": null,
"may88.com": null,
"mayclub.net": null,
"mc876.com": null,
"mclick.mobi": null,
"med.heyzap.com": null,
"media.adnetwork.vn": null,
"media.cachlammoi.com": null,
"media.dabong247.com": null,
"media.fastclick.net": null,
"media.net": null,
"mediad.asia": null,
"mediation.adnxs.com": null,
"mediaz.asia": null,
"mediaz.vn": null,
"mediazcorp.com": null,
"mega1.yeah1.com": null,
"mepuzz.com": null,
"metrics-dra.dt.hicloud.com": null,
"idaas-ext.cph.liveintent.com": null,
"metrics.coccoc.com": null,
"metrics.data.hicloud.com": null,
"x.bidswitch.net": null,
"metrics.mzstatic.com": null,
"metrics1.data.hicloud.com": null,
"metrics2.data.hicloud.com": null,
"metrics3.data.hicloud.com": null,
"metrics4.data.hicloud.com": null,
"metrics5.data.hicloud.com": null,
"metrika.yandex.ru": null,
"mibet.com": null,
"mibet.mobi": null,
"mibet.win": null,
"mibet88.com": null,
"mibet88.win": null,
"microad.vn": null,
"mid.rkdms.com": null,
"mig8vn.com": null,
"ministedik.info": null,
"mobile.adnxs.com": null,
"mobile.yandexadexchange.net": null,
"mobilead.vn": null,
"mobileads.dieuviet.com": null,
"mobio.vn": null,
"mobutrafsrcms.com": null,
"monitor.teko.vn": null,
"mouseflow.com": null,
"ms3388.com": null,
"ms88asia.com": null,
"ms88ca.com": null,
"mto.cgv.vn": null,
"munchkin.marketo.net": null,
"my.mobfox.com": null,
"myad.vn": null,
"mybestmv.com": null,
"myharavan.com": null,
"mysapo.net": null,
"nanda.vn": null,
"nbet.com": null,
"net.rayjump.com": null,
"newad.ifeng.com": null,
"newlog.daidoanket.vn": null,
"news-good.net": null,
"ng-vn-notice.gameitop.com": null,
"nhacainbet.club": null,
"nhanthuong88.com": null,
"nhat.game": null,
"nhatvip.net": null,
"nmetrics.samsung.com": null,
"notify.bugsnag.com": null,
"notify.mgid.com": null,
"ads.novanet.vn": null,
"novaon.asia": null,
"novaon.vn": null,
"novaonads.com": null,
"novaonx.com": null,
"ntv.bidvertiser.com": null,
"nv-ad.24hstatic.com": null,
"odr.mookie1.com": null,
"offerwall.headlines.pw": null,
"offerwall.yandex.net": null,
"ohchat.net": null,
"ole777vietnam.com": null,
"omarketer.viettelpost.vn": null,
"oncustomer.asia": null,
"one88.com": null,
"one88.fun": null,
"one88.me": null,
"one88.us": null,
"one88.vip": null,
"one88.vn": null,
"oneday88.com": null,
"onepush.query.yahoo.com": null,
"onfluencer.net": null,
"onmarketer.net": null,
"open.oneplus.net": null,
"oppa88888888.com": null,
"opus.analytics.yahoo.com": null,
"outcome.supersonicads.com": null,
"ox1.vietstock.vn": null,
"oxbet.club": null,
"oxbet.com": null,
"p-v2.presage.io": null,
"p232207.clksite.com": null,
"p232207.mybestmv.com": null,
"p232207.mycdn.co": null,
"pacman-cdn.sam-media.com": null,
"pad-v3.presage.io": null,
"pagead2.googleadservices.com": null,
"pagead46.l.doubleclick.net": null,
"partner.accesstrade.vn": null,
"partner.googleadservices.com": null,
"partnerad.l.doubleclick.net": null,
"partnerad.l.google.com": null,
"partnerads.ysm.yahoo.com": null,
"pclick.yahoo.com": null,
"pcookie.cnzz.com": null,
"pdn.applovin.com": null,
"performance.affiliaxe.com": null,
"phanquang.vn": null,
"static.piads.vn": null,
"phimmedia03.com": null,
"photo-ads.zaloapp.com": null,
"api.piads.vn": null,
"pinetech.vn": null,
"pix.as.criteo.net": null,
"pixel-tracking.sonic-us.supersonicads.com": null,
"pixel.33across.com": null,
"pixel.adsafeprotected.com": null,
"pixel.advertising.com": null,
"pixel.chotot.com": null,
"pixel.s3xified.com": null,
"pixel.servebom.com": null,
"pl-v2.presage.io": null,
"play.leadzu.com": null,
"playgamefa88.live": null,
"playgo88.asia": null,
"playv8.com": null,
"playv8.vip": null,
"polldaddy.com": null,
"polyad.net": null,
"thetradedesk.com": null,
"popads.net": null,
"popup.sapoapps.vn": null,
"pre.im": null,
"prebid.mgid.com": null,
"prequire.info": null,
"i.liadm.com": null,
"production-tracking.riviu.co": null,
"promotionpopup.sapoapps.vn": null,
"proton.flurry.com": null,
"publisher-event.ads.prd.ie.internal.unity3d.com": null,
"pubmatic.com": null,
"pushdi.com": null,
"pushdy.com": null,
"pushdy.vn": null,
"pushtimize.com": null,
"pv.sohu.com": null,
"q14.cnzz.com": null,
"qc-static.coccoc.com": null,
"qc.5giay.vn": null,
"qc.coccoc.com": null,
"qc.coccoc.vn": null,
"qc.designervn.net": null,
"qc.itsgroup.vn": null,
"qc.japo.vn": null,
"qc.violet.vn": null,
"qccoccocmedia.vn": null,
"qctt24h.24h.com.vn": null,
"qcv5.blogtruyen.vn": null,
"qq8788viet.com": null,
"quangcao.24h.com.vn": null,
"quangcao.baovannghe.com.vn": null,
"quangcao.eva.vn": null,
"quangcao.fff.com.vn": null,
"quangcao.thanhnien.vn": null,
"quangcao.tuoitre.vn": null,
"quangcao247.com.vn": null,
"r.remarketingpixel.com": null,
"r.tinmoi24.vn": null,
"r88.vn": null,
"realclick.vn": null,
"red88.com": null,
"red88.uk": null,
"redir.bebi.com": null,
"redir.jads.co": null,
"t.appsflyer.com": null,
"redirect.appmetrica.yandex.ru": null,
"redirector.gvt1.com": null,
"report.vnay.vn": null,
"reports.crashlytics.com": null,
"rereddit.com": null,
"res1.applovin.com": null,
"resentaticexhaus.info": null,
"resources.infolinks.com": null,
"ric.win": null,
"rik.vip": null,
"rik.win": null,
"rikvip.us": null,
"rio66qc.club": null,
"rituationscardb.info": null,
"router.infolinks.com": null,
"rsyslog.24h.com.vn": null,
"rt3011.infolinks.com": null,
"rt3015.infolinks.com": null,
"rt3020.infolinks.com": null,
"rt3033.infolinks.com": null,
"rtb.nexage.com": null,
"rtbvideobox.com": null,
"rubiconproject.com": null,
"rudy.adsnative.com": null,
"rungrinh.vn": null,
"s-img.mgid.com": null,
"s.amazon-adsystem.com": null,
"s.baomoi.xdn.vn": null,
"s.click.aliexpress.com": null,
"s.eclick.vn": null,
"s.giaoducthoidai.vn": null,
"s.homedy.com": null,
"s.kenh14.vn": null,
"s.soha.vn": null,
"s0.doubleclick.net": null,
"sa.api.intl.miui.com": null,
"sacchaeleduk.com": null,
"samsung-com.112.2o7.net": null,
"samsungadhub.com": null,
"samsungads.com": null,
"um.simpli.fi": null,
"sb.scorecardresearch.com": null,
"sbbanner-com.cdn.ampproject.org": null,
"sbc31.com": null,
"sbz.vn": null,
"sda.tamdiem247.com": null,
"sdk.iad-01.braze.com": null,
"sdkconfig.ad.intl.xiaomi.com": null,
"sdkconfig.ad.xiaomi.com": null,
"secure.adnxs.com": null,
"img-us.stripst.com": null,
"sentry.io": null,
"sentry.mediacdn.vn": null,
"service-api.accesstrade.vn": null,
"service.sponsorpay.com": null,
"serving-ad.tv24.vn": null,
"servs.adblox.net": null,
"sessions.bugsnag.com": null,
"setting.rayjump.com": null,
"i.bngprl.com": null,
"sg-pacman.sam-media.com": null,
"sharefb.cnnd.vn": null,
"sharethrough.adnxs.com": null,
"sharks.vn": null,
"shop-cdn.coccoc.com": null,
"shop.vnay.vn": null,
"shopping.coccoc.com": null,
"sieubomtan.com": null,
"sin1-mobile.adnxs.com": null,
"sin88.com": null,
"sinfb.adsrvr.org": null,
"sky88.com": null,
"slimads.vn": null,
"smartadserver.com": null,
"smartconvert.co": null,
"smetrics.kone.vn": null,
"hw-cdn2.adtng.com": null,
"smilitygorb.club": null,
"socvip.com": null,
"socvip9.club": null,
"sodo14.com": null,
"sourcetobin.com": null,
"sp.analytics.yahoo.com": null,
"sporttv.today": null,
"spouscontentdelivery.info": null,
"srv.svg.performancecentral.mobi": null,
"ssc-cms.33across.com": null,
"ssc.33across.com": null,
"ssl-avd.innity.net": null,
"adc3-launch.adcolony.com": null,
"ssl.cdne.cpmstar.com": null,
"f.novanet.vn": null,
"ads.avocarrot.com": null,
"sstatic1.histats.com": null,
"st-a.vtvdigital.vn": null,
"stage-assets.applovin.com": null,
"starseed.fr": null,
"stat.headlines.pw": null,
"stat.xiaomi.com": null,
"static-addtoany-com.cdn.ampproject.org": null,
"static.accesstrade.vn": null,
"static.ads-twitter.com": null,
"static.adsafeprotected.com": null,
"static.adsnative.com": null,
"static.adtima.vn": null,
"static.dulich9.com": null,
"static.exoclick.com": null,
"static.exosrv.com": null,
"static.gammaplatform.com": null,
"static.hadarone.com": null,
"static.hotjar.com": null,
"static.masoffer.net": null,
"static.media.net": null,
"static.mvot.vn": null,
"staticad.thethao247.vn": null,
"statis.dsp.vn": null,
"statistic.batdongsan.com.vn": null,
"statistics.tapchimypham.com.vn": null,
"ht-cdn2.adtng.com.sds.rncdn7.com": null,
"webgrouplimited.engine.adglare.net": null,
"stats.123c.vn": null,
"platform.bidgear.com": null,
"stats.bizweb.vn": null,
"stats.dongphim.net": null,
"stats.hstatic.net": null,
"vz-cdn2.adtng.com": null,
"stats.petrotimes.vn": null,
"stats.redditmedia.com": null,
"stats.tamdiem247.com": null,
"stats.vietnammoi.vn": null,
"stats.wp.com": null,
"statutorjuihui.site": null,
"stc-nas.nixcdn.com": null,
"stockbook-ads.firebaseapp.com": null,
"stockbook-ads.firebaseio.com": null,
"pub.yllix.com": null,
"subiz-cdn.com": null,
"subiz.com": null,
"subiz.com.vn": null,
"subiz.net": null,
"subiz.xyz": null,
"sun.win": null,
"supersonicads.com": null,
"img.stripst.com": null,
"surfcountor.com": null,
"survey.g.doubleclick.net": null,
"sv-api-event.headlines.pw": null,
"sv-api-lottery.headlines.pw": null,
"sv-static-lottery.headlines.pw": null,
"sv-static1-lottery.headlines.pw": null,
"sv88.com": null,
"sy-v1.presage.io": null,
"sync.crwdcntrl.net": null,
"sync.mathtag.com": null,
"sync.mazii.net": null,
"syndication.exdynsrv.com": null,
"syndication.exosrv.com": null,
"t.mobrand.net": null,
"t.sieu-viet.com": null,
"t8betvip.com": null,
"ta.toprework.vn": null,
"tag.adbro.me": null,
"tags.bluekai.com": null,
"tai789.net": null,
"taib52.club": null,
"taimacau.club": null,
"taiv8.com": null,
"taiv8.info": null,
"takataka.coccoc.com": null,
"tammenaa.com": null,
"tangsoc.com": null,
"tapad.com": null,
"test.niceios.com": null,
"testcentre.vn": null,
"tf88v.com": null,
"thethaodabet.com": null,
"thethaofb88.com": null,
"thethaovip.vip": null,
"thongke.24h.com.vn": null,
"thongke.baotintuc.vn": null,
"thongke.opencps.vn": null,
"thongke99.baogiaothong.vn": null,
"thseaeing.fun": null,
"tin010.com": null,
"tipkeomoingay.club": null,
"tknet.rayjump.com": null,
"tools.mgid.com": null,
"top88.club": null,
"top88.fun": null,
"top88.uk": null,
"top88.us": null,
"toppage.vn": null,
"tpmedia.online": null,
"tr.topdevvn.com": null,
"a.adtng.com": null,
"track.accesstrade.vn": null,
"track.adformnet.akadns.net": null,
"track.admobgeek.com": null,
"track.clickhubs.com": null,
"track.icheck.com.vn": null,
"track.kyna.vn": null,
"track.lapa.pub": null,
"track.lemonnovel.com": null,
"track.opticks.io": null,
"ib.adnxs.com": null,
"track.pregmomvietnam.com": null,
"track.sendo.vn": null,
"track.superfastmediation.com": null,
"track.vio.edu.vn": null,
"tracker.anime47.com": null,
"tracker.bongngo.store": null,
"exoclick.com": null,
"s3t3d2y7.ackcdn.net": null,
"tracker.tintucvietnam.vn": null,
"tracker.vanlong.stream": null,
"s-img.adskeeper.co.uk": null,
"tracking.api.media.zapps.vn": null,
"tracking.appwifi.com": null,
"a.realsrv.com": null,
"bidgear-syndication.com": null,
"tracking.fado.vn": null,
"tracking.fff.com.vn": null,
"tracking.gapone.vn": null,
"tracking.hongtinnhanh.com": null,
"tracking.intl.miui.com": null,
"tracking.meta.vn": null,
"ackcdn.net": null,
"tracking.sumatoad.com": null,
"pixel.onaudience.com": null,
"tracking.vietnamnetad.vn": null,
"trackingapi.foody.vn": null,
"bcp.crwdcntrl.net": null,
"onaudience.com": null,
"trck.bebi.com": null,
"trenddigital.vn": null,
"trending.vn": null,
"trends.revcontent.com": null,
"tricker.vn": null,
"trk.123c.vn": null,
"trk.pinterest.com": null,
"trk.staging.123c.vn": null,
"trk.superads.cn": null,
"trungso.vip": null,
"truoctran.com": null,
"tuiiu.com": null,
"tulipluv.xyz": null,
"tvnotice.kg.garena.vn": null,
"ucesreferre.club": null,
"unityads.unity3d.com": null,
"upfile16.mediaphim.com": null,
"us.adserver.yahoo.com": null,
"user.headlines.pw": null,
"creative.mdyjmp.com": null,
"ush.adspecs.yahoo.com": null,
"uw88vnd.com": null,
"v.mobfun.me": null,
"v2.chartboost.com": null,
"v7ac.com": null,
"v7king.com": null,
"v8.club": null,
"v9bet.com": null,
"v9jvn.com": null,
"vads.vn": null,
"vast.adsafeprotected.com": null,
"vast.adspruce.com": null,
"vclick.vn": null,
"viam.com.vn": null,
"vic.fun": null,
"vic.win": null,
"vicwin.vip": null,
"video-ad-stats.googlesyndication.com": null,
"video-native.mgid.com": null,
"video.adspruce.com": null,
"vidoomy.com": null,
"vieon-tracking.vieon.vn": null,
"vietbet.eu": null,
"vietbuzzad.com": null,
"vietdorje.com": null,
"vietnamnetad.vn": null,
"vinaads.vn": null,
"viva88.com": null,
"vlott88.com": null,
"vn-gmtdmp.mookie1.com": null,
"vn.adsloads.com": null,
"vn34.com": null,
"vn88.bet": null,
"vn88.biz": null,
"vn88.casino": null,
"vn88.club": null,
"vn88.com": null,
"vnd247.vn": null,
"vnloto.com": null,
"vnloto.vip": null,
"vnnayngaytin.vn": null,
"vongquaymienphi.net": null,
"vpaid.adsafeprotected.com": null,
"vtrack.vht.com.vn": null,
"vtvcab.xyz": null,
"vua1004.club": null,
"vua1005.club": null,
"vuabai9.com": null,
"vuaclub1008.club": null,
"vw220.com": null,
"vwinnow.com": null,
"vwinthethao.com": null,
"vx88.com": null,
"vx88e.com": null,
"vz681.com": null,
"w.cnzz.com": null,
"w388.com": null,
"w88.vin": null,
"w88bkk.com": null,
"w88bro.com": null,
"w88city.com": null,
"w88club.com": null,
"w88hn.com": null,
"w88yes.com": null,
"wakeup247.klick.vn": null,
"wbet99.net": null,
"web.api.adtimaserver.vn": null,
"web.hb.ad.cpe.dotomi.com": null,
"webad.fivecdm.com": null,
"webpush.bizfly.vn": null,
"webpush.todo.vn": null,
"webstag.kplus.vn": null,
"websvn.info": null,
"widget.headlines.pw": null,
"widget.kyna.vn": null,
"widgets.mgid.com": null,
"win888b.com": null,
"wsp.adskeeper.co.uk": null,
"wv.inner-active.mobi": null,
"ww88club.com": null,
"x8.club": null,
"x8.vin": null,
"x8vn.com": null,
"xapi.juicyads.com": null,
"xemdabanh.club": null,
"xml.ppc.buzz": null,
"yandexadexchange.net": null,
"yeah1media.vn": null,
"yeah1publishing.com": null,
"yo88.win": null,
"yo88vn.vip": null,
"younetmedia.com": null,
"cdn.stripst.com": null,
"yule12888.com": null,
"z.moatads.com": null,
"zalo-ads-240-td.zadn.vn": null,
"zalo-ads-240.zadn.vn": null,
"zalo-ads-480-td.zadn.vn": null,
"zalo-ads-480.zadn.vn": null,
"zalo-ads-td.zadn.vn": null,
"zalo-ads.zadn.vn": null,
"zaloads-480.zdn.vn": null,
"zbet.com": null,
"zbet.vn": null,
"zbet.win": null,
"zbetvn.com": null,
"zo.club": null,
"zo.game": null,
"zone.uniad.vn": null,
"zowinvn.vip": null,
"logging.admicro.vn": null,
"static-ssl.exoclick.com": null,
"main.exosrv.com": null,
"ads.exosrv.com": null,
"syndication.exosrv.com": null,
"lmadvertising.engine.adglare.net": null,
"reactads.cdn.adglare.net": null,
"s10.histats.com": null,
"ad.ezmob.com": null,
"xml.ezmob.com": null,
"is.yllix.com": null,
"apn.yllix.com": null,
"adv.yllix.com": null,
"banners.yllix.com": null,
"click2.yllix.com": null,
"click1.yllix.com": null,
"click.yllix.com": null,
"ad.propellerads.com": null,
"native.propellerads.com": null,
"offers.propellerads.com": null,
"partners.propellerads.com": null,
"promo.propellerads.com": null,
"publishers.propellerads.com": null,
"tracking.propellerads.com": null,
"alldcs.outbrain.com": null,
"amplify.outbrain.com": null,
"amplify-imp.outbrain.com": null,
"amplifypixel.outbrain.com": null,
"chi.outbrain.com": null,
"hpr.outbrain.com": null,
"images.outbrain.com": null,
"libs.outbrain.com": null,
"mcdp-chidc2.outbrain.com": null,
"mcdp-nydc1.outbrain.com": null,
"mcdp-sadc1.outbrain.com": null,
"mv.outbrain.com": null,
"ny.outbrain.com": null,
"odb.outbrain.com": null,
"revee.outbrain.com": null,
"sa.outbrain.com": null,
"stas.outbrain.com": null,
"sync.outbrain.com": null,
"vastcdn.outbrain.com": null,
"videoclientsservicescalls.outbrain.com": null,
"videoevents.outbrain.com": null,
"vrt.outbrain.com": null,
"widget-pixels.outbrain.com": null,
"widgetmonitor.outbrain.com": null,
"widgets.outbrain.com": null,
"api.dable.io": null,
"cdn.onthe.io": null,
"v7.cdn.onthe.io": null,
"as.v7.cdn.onthe.io": null,
"na.v7.cdn.onthe.io": null,
"i.onthe.io": null,
"tt.onthe.io": null,
"run-syndicate.com": null,
"cdn.run-syndicate.com.fpbns.net": null,
"pixel.runative-syndicate.com": null,
"cdn.run-syndicate.com": null,
"syndication.realsrv.com": null,
"realsrv.com": null,
"cdn.livechatinc.com": null,
"metrics.bangbros.com": null,
"tour.bangbros.com": null,
"twinrdsrv.com": null,
"stelagharris.com": null,
"go.xxxjmp.com": null,
"cdn.pncloudfl.com": null,
"cdnp.ad-stir.com": null,
"juryinvolving.com": null,
"my.rtmark.net": null,
"campjupiterjul.com": null,
"ancientsend.com": null,
"alcoholicsort.com": null,
"api6.storeip-mangun.io": null,
"qos-talk.123c.vn": null,
"cdn.pncloudfl.com.cdn.cloudflare.net": null,
"offerimage.com": null,
"pseepsie.com": null,
"ttt.onthe.io": null };
var bad_da_host_exact_flag = 1396 > 0 ? true : false;  // test for non-zero number of rules
    
// 35 rules as an efficient NFA RegExp:
var bad_da_host_RegExp = /"(?:tracking(?=([\s\S]*?\.euroads\.fi))\1|invenio_tracking_(?=([\s\S]*?\.sgnapps\.com))\2|mobileanalytics\.(?=([\s\S]*?\.amazonaws\.com))\3|ifengad\.(?=([\s\S]*?\.ifeng\.com))\4|imp(?=([\s\S]*?\.tradedoubler\.com))\5|rcm(?=([\s\S]*?\.amazon\.))\6|device\-metrics\-(?=([\s\S]*?\.amazon\.com))\7|metro\-trending\-(?=([\s\S]*?\.amazonaws\.com))\8|minero\-proxy\-(?=([\s\S]*?\.sh))\9|production\-adserver\-(?=([\s\S]*?\.amazonaws\.com))\10|adserver\.(?=([\s\S]*?\.yahoodns\.net))\11|rtbimp\-loadbalancer\-(?=([\s\S]*?\.amazonaws\.com))\12|vtnlog\-(?=([\s\S]*?\.elb\.amazonaws\.com))\13|s(?=([\s\S]*?\.site\.flashx\.))\14|metric(?=([\s\S]*?\.rediff\.com))\15|datacollect(?=([\s\S]*?\.abtasty\.com))\16|stats\-(?=([\s\S]*?\.p2pnow\.ru))\17|analytics\-beacon\-(?=([\s\S]*?\.amazonaws\.com))\18|log\-(?=([\s\S]*?\.previewnetworks\.com))\19|ad(?=([\s\S]*?\.nexage\.com))\20|collector\-(?=([\s\S]*?\.elb\.amazonaws\.com))\21|mediate\-ios\-(?=([\s\S]*?\.hyprmx\.com))\22|log(?=([\s\S]*?\.ku6\.com))\23|api(?=([\s\S]*?\.batmobil\.net))\24|banners(?=([\s\S]*?\.spacash\.com))\25|stats2\.(?=([\s\S]*?\.fdnames\.com))\26|sextronix\.(?=([\s\S]*?\.cdnaccess\.com))\27|flurry\.agentportal\-(?=([\s\S]*?\.yahoodns\.net))\28|flurry\.agentportal\.(?=([\s\S]*?\.yahoodns\.net))\29|collector\-(?=([\s\S]*?\.tvsquared\.com))\30|report(?=([\s\S]*?\.appmetrica\.webvisor\.com))\31|trk(?=([\s\S]*?\.vidible\.tv))\32|api(?=([\s\S]*?\.batmobi\.net))\33|logger\-(?=([\s\S]*?\.dailymotion\.com))\34|images\.(?=([\s\S]*?\.criteo\.net))\35)/i;
var bad_da_host_regex_flag = 35 > 0 ? true : false;  // test for non-zero number of rules

// 0 rules:
var bad_da_hostpath_JSON = { };
var bad_da_hostpath_exact_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 499 rules as an efficient NFA RegExp:
var bad_da_hostpath_RegExp = /^(?:[\w-]+\.)*?(?:piano\-media\.com\/uid\/|pornfanplace\.com\/js\/pops\.|pinterest\.com\/images\/|doubleclick\.net\/adx\/|google\-analytics\.com\/plugins\/|quantserve\.com\/pixel\/|baidu\.com\/pixel|nydailynews\.com\/img\/sponsor\/|porntube\.com\/adb\/|reddit\.com\/static\/|adf\.ly\/_|jobthread\.com\/t\/|netdna\-ssl\.com\/tracker\/|adform\.net\/banners\/|baidu\.com\/ecom|imageshack\.us\/ads\/|freakshare\.com\/banner\/|adultfriendfinder\.com\/banners\/|widgetserver\.com\/metrics\/|amazonaws\.com\/analytics\.|platform\.twitter\.com\/js\/button\.|google\-analytics\.com\/gtm\/js|oload\.tv\/log|facebook\.com\/tr|chaturbate\.com\/affiliates\/|openload\.co\/log|channel4\.com\/ad\/|streamango\.com\/log|doubleclick\.net\/adj\/|fwmrm\.net\/ad\/|google\.com\/analytics\/|addthiscdn\.com\/live\/|view\.atdmt\.com\/partner\/|domaintools\.com\/partners\/|redtube\.com\/stats\/|barnebys\.com\/widgets\/|adultfriendfinder\.com\/javascript\/|imagecarry\.com\/down|cursecdn\.com\/banner\/|cloudfront\.net\/track|visiblemeasures\.com\/log|twitter\.com\/javascripts\/|adultfriendfinder\.com\/go\/|pop6\.com\/banners\/|voyeurhit\.com\/contents\/content_sources\/|mediaplex\.com\/ad\/js\/|wtprn\.com\/sponsors\/|facebook\.com\/connect\/|pcwdld\.com\/wp\-content\/plugins\/wbounce\/|xvideos\-free\.com\/d\/|imagetwist\.com\/banner\/|wupload\.com\/referral\/|deadspin\.com\/sp\/|propelplus\.com\/track\/|veeseo\.com\/tracking\/|4tube\.com\/iframe\/|yandex\.st\/share\/|yahoo\.com\/beacon\/|yahoo\.com\/track\/|slashgear\.com\/stats\/|sextronix\.com\/images\/|healthtrader\.com\/banner\-|siberiantimes\.com\/counter\/|nydailynews\.com\/PCRichards\/|sex\.com\/popunder\/|thrixxx\.com\/affiliates\/|cloudfront\.net\/twitter\/|topbucks\.com\/popunder\/|pornoid\.com\/contents\/content_sources\/|video\-cdn\.abcnews\.com\/ad_|exitintel\.com\/log\/|github\.com\/_stats|hothardware\.com\/stats\/|doubleclick\.net\/ad\/|xxxhdd\.com\/contents\/content_sources\/|googlesyndication\.com\/sodar\/|googlesyndication\.com\/safeframe\/|powvideo\.net\/ban\/|red\-tube\.com\/popunder\/|primevideo\.com\/uedata\/|hstpnetwork\.com\/ads\/|pornalized\.com\/contents\/content_sources\/|doubleclick\.net\/pixel|soufun\.com\/stats\/|adroll\.com\/pixel\/|photobucket\.com\/track\/|shareasale\.com\/image\/|zawya\.com\/ads\/|appspot\.com\/stats|ad\.admitad\.com\/banner\/|lovefilm\.com\/partners\/|vodpod\.com\/stats\/|spacash\.com\/popup\/|wired\.com\/event|gamestar\.de\/_misc\/tracking\/|msn\.com\/tracker\/|chameleon\.ad\/banner\/|videowood\.tv\/ads|conduit\.com\/\/banners\/|soundcloud\.com\/event|rapidgator\.net\/images\/pics\/|amazonaws\.com\/fby\/|sawlive\.tv\/ad|livedoor\.com\/counter\/|phncdn\.com\/iframe|sydneyolympicfc\.com\/admin\/media_manager\/media\/mm_magic_display\/|daylogs\.com\/counter\/|twitter\.com\/i\/jot|fulltiltpoker\.com\/affiliates\/|cloudfront\.net\/facebook\/|hosting24\.com\/images\/banners\/|addthis\.com\/live\/|cnn\.com\/ad\-|ad\.atdmt\.com\/i\/img\/|sourceforge\.net\/log\/|quora\.com\/_\/ad\/|static\.criteo\.net\/js\/duplo[^\w.%-]|xhamster\.com\/ads\/|nytimes\.com\/ads\/|shareaholic\.com\/analytics_|sparklit\.com\/counter\/|cafemomstatic\.com\/images\/background\/|videoplaza\.tv\/proxy\/tracker[^\w.%-]|facebook\.com\/plugins\/follow|citygridmedia\.com\/ads\/|trustpilot\.com\/stats\/|worldfree4u\.top\/banners\/|ad\.atdmt\.com\/s\/|dailypioneer\.com\/images\/banners\/|secureupload\.eu\/banners\/|google\.com\/log|static\.criteo\.net\/images[^\w.%-]|google\-analytics\.com\/collect|filecrypt\.cc\/p\.|keepvid\.com\/ads\/|liutilities\.com\/partners\/|firedrive\.com\/tools\/|vidzi\.tv\/mp4|linkedin\.com\/img\/|dailymotion\.com\/track\-|dailymotion\.com\/track\/|mochiads\.com\/srv\/|baidu\.com\/billboard\/pushlog\/|girlfriendvideos\.com\/ad|tube18\.sex\/tube18\.|pornmaturetube\.com\/content\/|jdoqocy\.com\/image\-|tkqlhce\.com\/image\-|kqzyfj\.com\/image\-|xxvideo\.us\/ad728x15|allmyvideos\.net\/js\/ad_|ad\.admitad\.com\/fbanner\/|trrsf\.com\/metrics\/|youtube\.com\/pagead\/|cdn77\.org\/tags\/|mygaming\.co\.za\/news\/wp\-content\/wallpapers\/|videoplaza\.com\/proxy\/distributor\/|amazon\.com\/clog\/|theporncore\.com\/contents\/content_sources\/|ad\.atdmt\.com\/e\/|virool\.com\/widgets\/|3movs\.com\/contents\/content_sources\/|amazonaws\.com\/publishflow\/|amazonaws\.com\/ownlocal\-|facebook\.com\/plugins\/likebox\/|livefyre\.com\/tracking\/|broadbandgenie\.co\.uk\/widget|hulkload\.com\/b\/|internetbrands\.com\/partners\/|hentaistream\.com\/wp\-includes\/images\/bg\-|ad\.atdmt\.com\/m\/|andyhoppe\.com\/count\/|static\.criteo\.com\/images[^\w.%-]|ncrypt\.in\/images\/a\/|mtvnservices\.com\/metrics\/|softpedia\-static\.com\/images\/aff\/|filedownloader\.net\/design\/|banners\.friday\-ad\.co\.uk\/hpbanneruploads\/|sulia\.com\/papi\/sulia_partner\.js\/|amazonaws\.com\/bo\-assets\/production\/banner_attachments\/|static\.criteo\.com\/flash[^\w.%-]|bristolairport\.co\.uk\/~\/media\/images\/brs\/blocks\/internal\-promo\-block\-300x250\/|phncdn\.com\/images\/banners\/|tlavideo\.com\/affiliates\/|upsellit\.com\/custom\/|singlehop\.com\/affiliates\/|aliexpress\.com\/js\/beacon_|wishlistproducts\.com\/affiliatetools\/|advfn\.com\/tf_|doubleclick\.net\/pfadx\/video\.marketwatch\.com\/|recomendedsite\.com\/addon\/upixel\/|remixshop\.com\/bg\/site\/ajaxCheckCookiePolicy|creativecdn\.com\/pix\/|googleusercontent\.com\/tracker\/|autotrader\.co\.za\/partners\/|bluehost\-cdn\.com\/media\/partner\/images\/|vitalmtb\.com\/assets\/vital\.aba\-|chaturbate\.com\/creative\/|betwaypartners\.com\/affiliate_media\/|ebaystatic\.com\/aw\/signin\/ebay\-signin\-toyota\-|apester\.com\/event[^\w.%-]|sitegiant\.my\/affiliate\/|allanalpass\.com\/track\/|dailymotion\.com\/logger\/|foxadd\.com\/addon\/upixel\/|reevoo\.com\/track\/|questionmarket\.com\/static\/|googlesyndication\.com\/simgad\/|youtube\-nocookie\.com\/device_204|cloudfront\.net\/instagram\/|facebook\.com\/plugins\/subscribe|ad\.mo\.doubleclick\.net\/dartproxy\/|akamai\.net\/chartbeat\.|bridgetrack\.com\/site\/|vipbox\.tv\/js\/layer\-|camvideos\.tv\/tpd\.|dnsstuff\.com\/dnsmedia\/images\/ft\.banner\.|rt\.com\/static\/img\/banners\/|turnsocial\.com\/track\/|femalefirst\.co\.uk\/widgets\/|doubleclick\.net\/N2\/pfadx\/video\.wsj\.com\/|techkeels\.com\/creatives\/|h2porn\.com\/contents\/content_sources\/|bruteforcesocialmedia\.com\/affiliates\/|metromedia\.co\.za\/bannersys\/banners\/|thebull\.com\.au\/admin\/uploads\/banners\/|flixcart\.com\/affiliate\/|infibeam\.com\/affiliate\/|lawdepot\.com\/affiliate\/|seedsman\.com\/affiliate\/|couptopia\.com\/affiliate\/|theolympian\.com\/static\/images\/weathersponsor\/|bpath\.com\/affiliates\/|adm\.fwmrm\.net\/p\/mtvn_live\/|e\-tailwebstores\.com\/accounts\/default1\/banners\/|mrskin\.com\/data\/mrskincash\/|doubleclick\.net\/adx\/wn\.nat\.|carbiz\.in\/affiliates\-and\-partners\/|ibtimes\.com\/banner\/|majorgeeks\.com\/images\/download_sd_|dealextreme\.com\/affiliate_upload\/|inphonic\.com\/tracking\/|nspmotion\.com\/tracking\/|beacons\.vessel\-static\.com\/xff|lipsy\.co\.uk\/_assets\/images\/skin\/tracking\/|bigrock\.in\/affiliate\/|cnzz\.com\/stat\.|goldmoney\.com\/~\/media\/Images\/Banners\/|appinthestore\.com\/click\/|mrc\.org\/sites\/default\/files\/uploads\/images\/Collusion_Banner|yahooapis\.com\/get\/Valueclick\/CapAnywhere\.getAnnotationCallback|chaturbate\.com\/sitestats\/openwindow\/|bits\.wikimedia\.org\/geoiplookup|getreading\.co\.uk\/static\/img\/bg_takeover_|morningstaronline\.co\.uk\/offsite\/progressive\-listings\/|whozacunt\.com\/images\/banner_|mightydeals\.com\/widget|worddictionary\.co\.uk\/static\/\/inpage\-affinity\/|browsershots\.org\/static\/images\/creative\/|ad\.doubleclick\.net\/ddm\/trackclk\/|tehrantimes\.com\/banner\/|obox\-design\.com\/affiliate\-banners\/|vivatube\.com\/upload\/banners\/|pussycash\.com\/content\/banners\/|pixazza\.com\/track\/|sysomos\.com\/track\/|luminate\.com\/track\/|picbucks\.com\/track\/|ru4\.com\/click|targetspot\.com\/track\/|dw\.com\/tracking\/|clickandgo\.com\/booking\-form\-widget|theseblogs\.com\/visitScript\/|videos\.com\/click|share\-online\.biz\/affiliate\/|trustedreviews\.com\/mobile\/widgets\/html\/promoted\-phones|urlcash\.org\/banners\/|media\.domainking\.ng\/media\/|themis\-media\.com\/media\/global\/images\/cskins\/|whistleout\.com\.au\/imagelibrary\/ads\/wo_skin_|inhumanity\.com\/cdn\/affiliates\/|storage\.to\/affiliate\/|theday\.com\/assets\/images\/sponsorlogos\/|ctctcdn\.com\/js\/signup\-form\-widget\/|ehow\.com\/services\/jslogging\/log\/|brandcdn\.com\/pixel\/|wonderlabs\.com\/affiliate_pro\/banners\/|proxysolutions\.net\/affiliates\/|unblockedpiratebay\.com\/external\/|express\.de\/analytics\/|facebook\.com\/method\/links\.getStats|ppc\-coach\.com\/jamaffiliates\/|drivearchive\.co\.uk\/images\/amazon\.|googlesyndication\.com\/sadbundle\/|ad2links\.com\/js\/|gaccmidwest\.org\/uploads\/tx_bannermanagement\/|aftonbladet\.se\/blogportal\/view\/statistics|taboola\.com\/tb|media\.complex\.com\/videos\/prerolls\/|regnow\.img\.digitalriver\.com\/vendor\/37587\/ud_box|filez\.cutpaid\.com\/336v|amazonaws\.com\/statics\.reedge\.com\/|pan\.baidu\.com\/api\/analytics|hottubeclips\.com\/stxt\/banners\/|myanimelist\.cdn\-dena\.com\/images\/affiliates\/|examiner\.com\/sites\/all\/modules\/custom\/ex_stats\/|media\.enimgs\.net\/brand\/files\/escalatenetwork\/|groupon\.com\/tracking|expekt\.com\/affiliates\/|swurve\.com\/affiliates\/|axandra\.com\/affiliates\/|blissful\-sin\.com\/affiliates\/|singlemuslim\.com\/affiliates\/|mangaupdates\.com\/affiliates\/|bruteforceseo\.com\/affiliates\/|graduateinjapan\.com\/affiliates\/|punterlink\.co\.uk\/images\/storage\/siteban|bing\.com\/widget\/render\/|itweb\.co\.za\/logos\/|tvducky\.com\/imgs\/graboid\.|worldradio\.ch\/site_media\/banners\/|epictv\.com\/sites\/default\/files\/290x400_|viglink\.com\/api\/batch[^\w.%-]|updatetube\.com\/iframes\/|yyv\.co\/track\/|visa\.com\/logging\/logEvent|jenningsforddirect\.co\.uk\/sitewide\/extras\/|sectools\.org\/shared\/images\/p\/|thrillist\.com\/track|zap2it\.com\/wp\-content\/themes\/overmind\/js\/zcode\-|twitch\.tv\/track\/|pwpwpoker\.com\/images\/banners\/|aerotime\.aero\/upload\/banner\/|vindicosuite\.com\/tracking\/|channel4\.com\/assets\/programmes\/images\/originals\/|services\.webklipper\.com\/geoip\/|ejpress\.org\/img\/banners\/|vipstatic\.com\/mars\/|appwork\.org\/hoster\/banner_|bwwstatic\.com\/socialtop|wwe\.com\/sites\/all\/modules\/wwe\/wwe_analytics\/|amarotic\.com\/Banner\/|dota\-trade\.com\/img\/branding_|xscores\.com\/livescore\/banners\/|talkphotography\.co\.uk\/images\/externallogos\/banners\/|debtconsolidationcare\.com\/affiliate\/tracker\/|getadblock\.com\/images\/adblock_banners\/|tsite\.jp\/static\/analytics\/|accuradio\.com\/static\/track\/|nfl\.com\/assets\/images\/hp\-poweredby\-|redditstatic\.com\/moat\/|parliamentlive\.tv\/cookie\/|djmag\.co\.uk\/sites\/default\/files\/takeover\/|chefkoch\.de\/counter|celebstoner\.com\/assets\/components\/bdlistings\/uploads\/|adm24\.de\/hp_counter\/|ball2win\.com\/Affiliate\/|flipkart\.com\/ajaxlog\/visitIdlog|ironsquid\.tv\/data\/uploads\/sponsors\/|thelodownny\.com\/leslog\/ads\/|olark\.com\/track\/|cumulus\-cloud\.com\/trackers\/|t5\.ro\/static\/|vpnarea\.com\/affiliate\/|relink\.us\/images\/|shinypics\.com\/blogbanner\/|sacbee\.com\/static\/dealsaver\/|borrowlenses\.com\/affiliate\/|thereadystore\.com\/affiliate\/|drom\.ru\/dummy\.|moneycontrol\.co\.in\/images\/promo\/|adyou\.me\/bug\/adcash|amazon\.com\/gp\/yourstore\/recs\/|totallylayouts\.com\/online\-users\-counter\/|cloudfront\.net\/linkedin\/|nudography\.com\/photos\/banners\/|homoactive\.tv\/banner\/|go\.com\/stat\/|ziffstatic\.com\/jst\/zdvtools\.|nmap\.org\/shared\/images\/p\/|lumfile\.com\/lumimage\/ourbanner\/|seclists\.org\/shared\/images\/p\/|amazonaws\.com\/btrb\-prd\-banners\/|brettterpstra\.com\/wp\-content\/uploads\/|inquirer\.net\/wp\-content\/themes\/news\/images\/wallpaper_|americanfreepress\.net\/assets\/images\/Banner_|golem\.de\/staticrl\/scripts\/golem_cpxl_|dailymail\.co\.uk\/tracking\/|aebn\.net\/banners\/|1320wils\.com\/assets\/images\/promo%20banner\/|createtv\.com\/CreateProgram\.nsf\/vShowcaseFeaturedSideContentByLinkTitle\/|knco\.com\/wp\-content\/uploads\/wpt\/|mixpanel\.com\/track|vindicosuite\.com\/track\/|download\.bitdefender\.com\/resources\/media\/|static\.multiplayuk\.com\/images\/w\/w\-|a\.huluad\.com\/beacons\/|petri\.co\.il\/wp\-content\/uploads\/banner1000x75_|petri\.co\.il\/wp\-content\/uploads\/banner700x475_|facebook\.com\/friends\/requests\/log_impressions|go2cdn\.org\/brand\/|c21media\.net\/wp\-content\/plugins\/sam\-images\/|googlesyndication\.com\/ddm\/|spiceworks\.com\/share\/|zanox\-affiliate\.de\/ppv\/|imdb\.com\/tr\/|avira\.com\/site\/datatracking|watchuseek\.com\/media\/1900x220_|sextvx\.com\/static\/images\/tpd\-|videowood\.tv\/pop2|amazonaws\.com\/new\.cetrk\.com\/|draugiem\.lv\/lapas\/widgets\/|toolslib\.net\/assets\/img\/a_dvt\/|rbth\.ru\/widget\/|twitter\.com\/abacus|text\-compare\.com\/media\/global_vision_banner_|video\.mediaset\.it\/polymediashowanalytics\/|betterbills\.com\.au\/widgets\/|ask\.com\/servlets\/ulog|purevpn\.com\/affiliates\/|nation\.sc\/images\/banners\/|safarinow\.com\/affiliate\-zone\/|metroweekly\.com\/tools\/blog_add_visitor\/|freemoviestream\.xyz\/wp\-content\/uploads\/|dx\.com\/affiliate\/|premiumtradings\.com\/media\/images\/index_banners\/|smn\-news\.com\/images\/banners\/|apple\.com\/itunesaffiliates\/|s3\.amazonaws\.com\/draftset\/banners\/|lgoat\.com\/cdn\/amz_|ziffstatic\.com\/jst\/zdsticky\.|sapeople\.com\/wp\-content\/uploads\/wp\-banners\/|tshirthell\.com\/img\/affiliate_section\/|gaccny\.com\/uploads\/tx_bannermanagement\/|ahk\-usa\.com\/uploads\/tx_bannermanagement\/|gaccwest\.com\/uploads\/tx_bannermanagement\/|gaccsouth\.com\/uploads\/tx_bannermanagement\/|yea\.xxx\/img\/creatives\/|wykop\.pl\/dataprovider\/diggerwidget\/|babyblog\.ru\/pixel|russian\-dreams\.net\/static\/js\/|thesundaily\.my\/sites\/default\/files\/twinskyscrapers|plugins\.longtailvideo\.com\/yourlytics|cdn\.69games\.xxx\/common\/images\/friends\/|saabsunited\.com\/wp\-content\/uploads\/180x460_|saabsunited\.com\/wp\-content\/uploads\/werbung\-|any\.gs\/visitScript\/|djmag\.com\/sites\/default\/files\/takeover\/|110\.45\.173\.103\/ad\/|amazonaws\.com\/streetpulse\/ads\/|getnzb\.com\/img\/partner\/banners\/|camwhores\.tv\/contents\/other\/player\/|oodle\.co\.uk\/event\/track\-first\-view\/|jobs\-affiliates\.ws\/images\/|webdesignerdepot\.com\/wp\-content\/plugins\/md\-popup\/|hardsextube\.com\/preroll\/getiton\/|fairfaxregional\.com\.au\/proxy\/commercial\-partner\-solar\/|mcvuk\.com\/static\/banners\/|gadget\.co\.za\/siteimages\/banners\/|nutritionhorizon\.com\/content\/banners\/|preisvergleich\.de\/setcookie\/|adsl2exchanges\.com\.au\/images\/spintel|uploading\.com\/static\/banners\/|doubleclick\.net\/pfadx\/intl\.sps\.com\/|graboid\.com\/affiliates\/|doubleclick\.net\/N6872\/pfadx\/shaw\.mylifetimetv\.ca\/|nigeriafootball\.com\/img\/affiliate_|iradio\.ie\/assets\/img\/backgrounds\/|videos\.mediaite\.com\/decor\/live\/white_alpha_60\.|twitter\.com\/scribes\/|hostdime\.com\/images\/affiliate\/|attn\.com\/survey|usps\.com\/survey\/|dreamstime\.com\/refbanner\-|virtualhottie2\.com\/cash\/tools\/banners\/|yimg\.com\/uq\/syndication\/|presscoders\.com\/wp\-content\/uploads\/misc\/aff\/|govevents\.com\/display\-file\/|pedestrian\.tv\/_crunk\/wp\-content\/files_flutter\/|citeulike\.org\/static\/campaigns\/|geometria\.tv\/banners\/|suite101\.com\/tracking\/|digitalsatellite\.tv\/banners\/|gamefront\.com\/wp\-content\/plugins\/tracker\/|salemwebnetwork\.com\/Stations\/images\/SiteWrapper\/|customerlobby\.com\/ctrack\-|tourradar\.com\/def\/partner|foxtel\.com\.au\/cms\/fragments\/corp_analytics\/|vator\.tv\/tracking\/|putpat\.tv\/tracking|oasap\.com\/images\/affiliate\/|videovalis\.tv\/tracking\/|nijobfinder\.co\.uk\/affiliates\/|desperateseller\.co\.uk\/affiliates\/|timesinternet\.in\/ad\/|moneywise\.co\.uk\/affiliate\/|doubleclick\.net\/json|porn2blog\.com\/wp\-content\/banners\/|vigilante\.pw\/img\/partners\/)/i;
var bad_da_hostpath_regex_flag = 499 > 0 ? true : false;  // test for non-zero number of rules
    
// 212 rules as an efficient NFA RegExp:
var bad_da_RegExp = /^(?:[\w-]+\.)*?(?:porntube\.com\/ads$|ads\.|adv\.|1337x\.to[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|erotikdeal\.com\/\?ref=|banner\.|affiliates\.|torrentz2\.eu[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|banners\.|synad\.|quantserve\.com\/pixel;|affiliate\.|cloudfront\.net\/\?a=|ad\.atdmt\.com\/i\/go;|api\-read\.facebook\.com\/restserver\.php\?api_key=|kickass2\.st[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|katcr\.co[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|bittorrent\.am[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|graph\.facebook\.com\/fql\?q=SELECT|oddschecker\.com\/clickout\.htm\?type=takeover\-|torrentdownloads\.me[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|movies\.askjolene\.com\/c64\?clickid=|cloudfront\.net\/\?tid=|ipornia\.com\/scj\/cgi\/out\.php\?scheme_id=|yahoo\.com\/p\.gif;|api\.ticketnetwork\.com\/Events\/TopSelling\/domain=nytimes\.com|sweed\.to\/\?pid=|qualtrics\.com\/WRSiteInterceptEngine\/\?Q_Impress=|x1337x\.ws[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|tube911\.com\/scj\/cgi\/out\.php\?scheme_id=|nowwatchtvlive\.ws[^\w.%-]\$csp=script\-src 'self' |amazonaws\.com\/\?wsid=|watchsomuch\.info[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|sponsorselect\.com\/Common\/LandingPage\.aspx\?eu=|gawker\.com\/\?op=hyperion_useragent_data|torrentdownload\.ch[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|torrentfunk2\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|uploadproper\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|pirateiro\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|magnetdl\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|yifyddl\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|watchfree\.to\/download\.php\?type=1&title=|yourbittorrent2\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|limetorrents\.info[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|videobox\.com\/\?tid=|mail\.yahoo\.com\/neo\/mbimg\?av\/curveball\/ds\/|totalporn\.com\/videos\/tracking\/\?url=|x1337x\.se[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|affiliates2\.|977music\.com\/index\.php\?p=get_loading_banner|plista\.com\/async\/min\/video,outstream\/|google\.com\/uds\/\?file=orkut&|irs01\.|1337x\.st[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|elb\.amazonaws\.com\/\?page=|777livecams\.com\/\?id=|eurolive\.com\/index\.php\?module=public_eurolive_onlinetool&|inn\.co\.il\/Controls\/HPJS\.ashx\?act=log|bluehost\.com\/web\-hosting\/domaincheckapi\/\?affiliate=|eurolive\.com\/\?module=public_eurolive_onlinehostess&|ooyala\.com\/authorized\?analytics|yahoo\.com\/serv\?s|ab\-in\-den\-urlaub\.de\/resources\/cjs\/\?f=\/resources\/cjs\/tracking\/|oneload\.site[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|yahoo\.com\/yi\?bv=|google\.com\/_\/\+1\/|x1337x\.eu[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|jewsnews\.co\.il[^\w.%-]\$csp=script\-src 'self' |247hd\.net\/ad$|monova\.org[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|comicgenesis\.com\/tcontent\.php\?out=|plista\.com\/jsmodule\/flash$|seedpeer\.me[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|gameknot\.com\/amaster\.pl\?j=|rehost\.to\/\?ref=|tinypic\.com\/api\.php\?(?=([\s\S]*?&action=track))\1|t\-online\.de[^\w.%-](?=([\s\S]*?\/stats\.js\?track=))\2|casino\-x\.com[^\w.%-](?=([\s\S]*?\?partner=))\3|allmyvideos\.net\/(?=([\s\S]*?=))\4|swatchseries\.to[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\5|ad\.atdmt\.com\/i\/(?=([\s\S]*?=))\6|blacklistednews\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\7|exashare\.com[^\w.%-](?=([\s\S]*?&h=))\8|acidcow\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\9|uptobox\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline' ))\10(?=([\s\S]*?\.gstatic\.com ))\11(?=([\s\S]*?\.google\.com ))\12(?=([\s\S]*?\.googleapis\.com))\13|thevideo\.me\/(?=([\s\S]*?\:))\14|fantasti\.cc[^\w.%-](?=([\s\S]*?\?ad=))\15|androidcentral\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\16|phonearena\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\17|quantserve\.com[^\w.%-](?=([\s\S]*?[^\w.%-]a=))\18|merriam\-webster\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\19|2hot4fb\.com\/img\/(?=([\s\S]*?\.gif\?r=))\20|doubleclick\.net[^\w.%-](?=([\s\S]*?;afv_flvurl=http\:\/\/cdn\.c\.ooyala\.com\/))\21|watchcartoononline\.io[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\22|flirt4free\.com[^\w.%-](?=([\s\S]*?&utm_campaign))\23|activistpost\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\24|plista\.com\/widgetdata\.php\?(?=([\s\S]*?%22pictureads%22%7D))\25|shortcuts\.search\.yahoo\.com[^\w.%-](?=([\s\S]*?&callback=yahoo\.shortcuts\.utils\.setdittoadcontents&))\26|media\.campartner\.com\/index\.php\?cpID=(?=([\s\S]*?&cpMID=))\27|eafyfsuh\.net[^\w.%-](?=([\s\S]*?\/\?name=))\28|linkbucks\.com[^\w.%-](?=([\s\S]*?\/\?))\29(?=([\s\S]*?=))\30|unblockall\.org[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\31|answerology\.com\/index\.aspx\?(?=([\s\S]*?=ads\.ascx))\32|trove\.com[^\w.%-](?=([\s\S]*?&uid=))\33|videolike\.org[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\34|freehostedscripts\.net[^\w.%-](?=([\s\S]*?\.php\?site=))\35(?=([\s\S]*?&s=))\36(?=([\s\S]*?&h=))\37|widgets\.itunes\.apple\.com[^\w.%-](?=([\s\S]*?&affiliate_id=))\38|solarmovie\.one[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\39|facebook\.com\/restserver\.php\?(?=([\s\S]*?\.getStats&))\40|facebook\.com\/(?=([\s\S]*?\/plugins\/send_to_messenger\.php\?app_id=))\41|hop\.clickbank\.net\/(?=([\s\S]*?&transaction_id=))\42(?=([\s\S]*?&offer_id=))\43|freebeacon\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\44|biology\-online\.org[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\45|facebook\.com\/connect\/connect\.php\?(?=([\s\S]*?width))\46(?=([\s\S]*?&height))\47|tipico\.com[^\w.%-](?=([\s\S]*?\?affiliateid=))\48|readcomiconline\.to[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline' (?=([\s\S]*?\.disquscdn\.com ))\49(?=([\s\S]*?\.disqus\.com))\50|tipico\.(?=([\s\S]*?\?affiliateId=))\51|rover\.ebay\.com\.au[^\w.%-](?=([\s\S]*?&cguid=))\52|onion\.ly[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\53|l\.yimg\.com[^\w.%-](?=([\s\S]*?&partner=))\54(?=([\s\S]*?&url=))\55|miniurls\.co[^\w.%-](?=([\s\S]*?\?ref=))\56|computerarts\.co\.uk\/(?=([\s\S]*?\.php\?cmd=site\-stats))\57|zabasearch\.com\/search_box\.php\?(?=([\s\S]*?&adword=))\58|plarium\.com\/play\/(?=([\s\S]*?adCampaign=))\59|convertcase\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\60|gogoanimes\.co[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? disquscdn\.com 'unsafe\-inline'))\61|prox4you\.pw[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\62|broadwayworld\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\63|123unblock\.xyz[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\64|cts\.tradepub\.com\/cts4\/\?ptnr=(?=([\s\S]*?&tm=))\65|twitter\.com\/i\/cards\/tfw\/(?=([\s\S]*?\?advertiser_name=))\66|media\.campartner\.com[^\w.%-](?=([\s\S]*?\?cp=))\67|ebayobjects\.com\/(?=([\s\S]*?;dc_pixel_url=))\68|freean\.us[^\w.%-](?=([\s\S]*?\?ref=))\69|fullmatchesandshows\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\70|nintendoeverything\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\71|textsfromlastnight\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\72|powerofpositivity\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\73|talkwithstranger\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\74|roadracerunner\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\75|pockettactics\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\76|tetrisfriends\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\77|almasdarnews\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\78|colourlovers\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\79|convertfiles\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\80|investopedia\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\81|skidrowcrack\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\82|sportspickle\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\83|kshowonline\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\84|moneyversed\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\85|thehornnews\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\86|torrentfunk\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\87|britannica\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\88|csgolounge\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\89|grammarist\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\90|healthline\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\91|tworeddots\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\92|wuxiaworld\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\93|kiplinger\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\94|readmng\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\95|trifind\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\96|yimg\.com[^\w.%-](?=([\s\S]*?\/l\?ig=))\97|campussports\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\98|ancient\-origins\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\99|yahoo\.(?=([\s\S]*?\/serv\?s=))\100|newser\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\101|winit\.winchristmas\.co\.uk[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\102|assoc\-amazon\.(?=([\s\S]*?[^\w.%-]e\/ir\?t=))\103|bittorrentstart\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline' data\: (?=([\s\S]*?\.google\.com ))\104(?=([\s\S]*?\.google\-analytics\.com ))\105(?=([\s\S]*?\.scorecardresearch\.com))\106|daclips\.in[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\107|lolcounter\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\108|nsfwyoutube\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\109|unlockproject\.icu[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\110|mrunlock\.icu[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\111|tamilo\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\112|datpiff\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\113|allthetests\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\114|hiphoplately\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\115|breakingisraelnews\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\116|mjtlive\.com\/exports\/golive\/\?lp=(?=([\s\S]*?&afno=))\117|r\.ypcdn\.com[^\w.%-](?=([\s\S]*?\/rtd\?ptid))\118|unblocked\.app[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\119|moviewatcher\.is[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\120|c\.ypcdn\.com[^\w.%-](?=([\s\S]*?\/webyp\?rid=))\121|static\.hd\-trailers\.net\/js\/javascript_(?=([\s\S]*?\.js$))\122|cyberprotection\.pro[^\w.%-](?=([\s\S]*?\?aff))\123|google\.(?=([\s\S]*?\/stats\?frame=))\124|phonesreview\.co\.uk[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\125|unblocked\.si[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\126|torrentz\.eu\/search(?=([\s\S]*?=))\127|shopify\.com\/(?=([\s\S]*?\/page\?))\128(?=([\s\S]*?&eventType=))\129|unblocked\.llc[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\130|nocensor\.pro[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\131|waybig\.com\/blog\/wp\-content\/uploads\/(?=([\s\S]*?\?pas=))\132|filefactory\.com[^\w.%-](?=([\s\S]*?\/refer\.php\?hash=))\133|netflix\.com\/beacons\?(?=([\s\S]*?&ssizeCat=))\134(?=([\s\S]*?&vsizeCat=))\135|unblocked\.lol[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\136|solarmoviez\.ru[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\137|amazon\.com\/gp\/(?=([\s\S]*?&linkCode))\138|downloadprovider\.me\/en\/search\/(?=([\s\S]*?\?aff\.id=))\139(?=([\s\S]*?&iframe=))\140|clickbank\.net\/(?=([\s\S]*?offer_id=))\141|amazonaws\.com\/betpawa\-(?=([\s\S]*?\.html\?aff=))\142|huluim\.com\/(?=([\s\S]*?&beaconevent))\143|ifly\.com\/trip\-plan\/ifly\-trip\?(?=([\s\S]*?&ad=))\144|deals4thecure\.com\/widgets\/(?=([\s\S]*?\?affiliateurl=))\145|online\.mydirtyhobby\.com[^\w.%-](?=([\s\S]*?\?naff=))\146|c\.ypcdn\.com[^\w.%-](?=([\s\S]*?&ptid))\147|c\.ypcdn\.com[^\w.%-](?=([\s\S]*?\?ptid))\148|events\.eyeviewdigital\.com[^\w.%-](?=([\s\S]*?\.gif\?r=))\149|cloudfront\.net(?=([\s\S]*?\/sp\.js$))\150|bitcoinist\.net\/wp\-content\/(?=([\s\S]*?\/g\+\.png))\151|onhax\.me[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\152)/i;
var bad_da_regex_flag = 212 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_url_parts_RegExp = /^$/;
var good_url_parts_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 499 rules as an efficient NFA RegExp:
var bad_url_parts_RegExp = /(?:\/adcontent\.|\/adsys\/|\/adserver\.|\/img\/tumblr\-|\/pp\-ad\.|\.com\/ads\?|\?getad=&|\/social\-media\.|\/social_media\/|\/expandable_ad\?|\/img\/adv\.|\/img\/adv\/|\/homepage\-ads\/|\/homepage\/ads\/|\/ad_pop\.php\?|\/ad\-engine\.|\/ad_engine\?|\-web\-ad\-|\/web\-ad_|\-leaderboard\-ad\-|\/leaderboard_ad\.|\/leaderboard_ad\/|\/imgad\.|\/imgad\?|\/iframead\.|\/iframead\/|\/contentad\/|\/contentad$|\-ad\-content\/|\/ad\/content\/|\/ad_content\.|\/adcontent\/|\/ad\-image\.|\/ad\/image\/|\/ad_image\.|\/ad\-images\/|\/ad\/images\/|\/ad_images\/|\-online\-advert\.|\/webad\?|_webad\.|\/adplugin\.|\/adplugin\/|\/adplugin_|\-iframe\-ad\.|\/iframe\-ad\.|\/iframe\-ad\/|\/iframe\-ad\?|\/iframe\.ad\/|\/iframe\/ad\/|\/iframe\/ad_|\/iframe_ad\.|\/iframe_ad\?|\-content\-ad\-|\-content\-ad\.|\/content\/ad\/|\/content\/ad_|\/content_ad\.|_content_ad\.|\/eu_cookies\.|\/online\-ad_|_online_ad\.|\.com\/video\-ad\-|\/video\-ad\.|\/video\/ad\/|\/video_ad\.|\.cookie_law\.|\/cookie_law\/|\/static\/tracking\/|_js\/ads\.js|\/cookie\-information\.|\-ad_leaderboard\/|\/ad\-leaderboard\.|\/ad\/leaderboard\.|\/ad_leaderboard\.|\/ad_leaderboard\/|=ad\-leaderboard\-|\/cookiecompliance\.|=adcenter&|\/_img\/ad_|\/img\/_ad\.|\/img\/ad\-|\/img\/ad\.|\/img\/ad\/|\/img_ad\/|\/superads_|\/eu\-cookie\.|\/eu\-cookie\/|_eu_cookie\.|_eu_cookie_|\/t\/event\.js\?|\/web\-analytics\.|\/web_analytics\/|\.com\/\?adv=|\/popad$|\/cookie\-consent\.|\/cookie\-consent\/|\/cookie\-consent\?|\/cookie_consent\.|\/cookie_consent\/|\/cookie_consent_|_cookie_consent\/|\-ad\-iframe\.|\-ad\-iframe\/|\-ad\/iframe\/|\/ad\-iframe\-|\/ad\-iframe\.|\/ad\-iframe\?|\/ad\/iframe\.|\/ad\/iframe\/|\/ad\?iframe_|\/ad_iframe\.|\/ad_iframe_|=ad_iframe&|=ad_iframe_|\-CookieInfo\.|\/CookieInfo\.|\.adriver\.|\/adriver\.|\/adriver_|\/ad\.php$|\/pop2\.js$|\/bottom\-ads\.|\/expandable_ad\.php|_search\/ads\.js|\/ad132m\/|\/post\/ads\/|\/bg\/ads\/|\/xtclicks\.|\/xtclicks_|\.cookienotice\.|\/cookienotice\-|\/cookienotice\.|\/footer\-ads\/|\/adclick\.|\-show\-ads\.|\/show\-ads\.|\-top\-ads\.|\/top\-ads\.|\-text\-ads\.|\/media\/ad\/|\/afs\/ads\/|\-ads\-iframe\.|\/ads\/iframe|\/ads_iframe\.|\-iframe\-ads\/|\/iframe\-ads\/|\/iframe\/ads\/|\/twittericon\.|\/facebookicon\.|\/mobile\-ads\/|\.co\/ads\/|\/dynamic\/ads\/|\/special\-ads\/|\/socialmedia_|\/user\/ads\?|\/js\/ads\-|\/js\/ads\.|\/js\/ads_|\/pc\/ads\.|\/cms\/ads\/|\/modules\/ads\/|\/ads\.cms|\/ads\/html\/|\/showads\/|\/ad\?count=|\/ad_count\.|\/i\/ads\/|\/player\/ads\.|\/player\/ads\/|\.no\/ads\/|\-video\-ads\/|\/video\-ads\/|\/video\.ads\.|\/video\/ads\/|\/ext\/ads\/|\/custom\/ads|\/vast\/ads\-|\/default\/ads\/|\/mini\-ads\/|\/external\/ads\/|\/left\-ads\.|\/delivery\.ads\.|\/ad\/logo\/|\/responsive\-ads\.|\/sidebar\-ads\/|&program=revshare&|_track\/ad\/|\/inc\/ads\/|\/jssocials\-|\/jssocials_|\/remove\-ads\.|\.net\/ad\/|\/house\-ads\/|\/ads12\.|\/ads\/async\/|\-adskin\.|\/adskin\/|\/ad\?sponsor=|\/ads\/click\?|\/adsetup\.|\/adsetup_|\/adsframe\.|\/td\-ads\-|\/adsdaq_|\/click\?adv=|\/social\-likes\-|\/adbanners\/|\/blogad\.|\/analytics\.gif\?|\/popupads\.|\/ads\.htm|\/ads\/targeting\.|\/adv\-socialbar\-|\/click\.track\?|\/adsrv\.|\/adsrv\/|\/ads_reporting\/|\.ads\.css|\/ads\.css|\.online\/ads\/|\/online\/ads\/|\/image\/ads\/|\/image\/ads_|\/banner\-adv\-|\/banner\/adv\/|\/banner\/adv_|\-peel\-ads\-|\.com\/js\/ads\/|\/adlog\.|\/adsys\.|&adcount=|\/aff_ad\?|\/partner\.ads\.|\.link\/ads\/|\/social\-media\-banner\.|\/ads\.php|\/ads_php\/|\/ads\/square\-|\/ads\/square\.|\/plugins\/ads\-|\/plugins\/ads\/|\/log\/ad\-|\/log_ad\?|\/sharebar\.|\-sharebar\-|\-sharebar\.|\/sponsored_ad\.|\/sponsored_ad\/|\/realmedia\/ads\/|\/ads8\.|\/ads8\/|\/adsjs\.|\/adsjs\/|\.ads1\-|\.ads1\.|\/ads1\.|\/ads1\/|\/video\-ad\-overlay\.|\/new\-ads\/|\/new\/ads\/|\/adstop\.|\/adstop_|\-adsonar\.|\/adsonar\.|\/ads\.js\.|\/ads\.js\/|\/ads\.js\?|\/ads\/js\.|\/ads\/js\/|\/ads\/js_|\/adpartner\.|\?adpartner=|\-adbanner\.|\.adbanner\.|\/adbanner\.|\/adbanner\/|\/adbanner_|=adbanner_|=popunders&|\/flash\-ads\.|\/flash\-ads\/|\/flash\/ads\/|\/bin\/stats\?|\/icon\/share\-|\.adserve\.|\/adserve\-|\/adserve\.|\/adserve\/|\/adserve_|\/lazy\-ads\-|\/lazy\-ads\.|&popunder=|\/popunder\.|\/popunder_|=popunder&|_popunder\+|\/blog\/ads\/|\/ad\.html\?|\/ad\/html\/|\/ad_html\/|\/adClick\/|\/adClick\?|\/home\/ads\-|\/home\/ads\/|\/home\/ads_|\.ads9\.|\/ads9\.|\/ads9\/|\-adsystem\-|\/adsystem\.|\/adsystem\/|\.ads3\-|\/ads3\.|\/ads3\/|\-banner\-ads\-|\-banner\-ads\/|\/banner\-ads\-|\/banner\-ads\/|\/ads\-new\.|\/ads_new\.|\/ads_new\/|\/bannerad\.|\/bannerad\/|_bannerad\.|\/s_ad\.aspx\?|\/ads\/index\-|\/ads\/index\.|\/ads\/index\/|\/ads\/index_|&adspace=|\-adspace\.|\-adspace_|\.adspace\.|\/adspace\.|\/adspace\/|\/adspace\?|\/google\/adv\.|\/ads\/text\/|\/ads_text_|\.adsense\.|\/adsense\-|\/adsense\/|\/adsense\?|;adsense_|\/img\/social\/|\/ads\-top\.|\/ads\/top\-|\/ads\/top\.|\/ads_top_|\-adscript\.|\/adscript\.|\/adscript\?|\/adscript_|\/pages\/ads|\/site\-ads\/|\/site\/ads\/|\/site\/ads\?|\/google_tag\.|\/google_tag\/|\/web\-ads\.|\/web\-ads\/|\/web\/ads\/|=web&ads=|\/adstat\.|\-social\-share\/|\-social\-share_|\.social\/share\/|\/social\-share\-|\/social\/share\-|\/social\/share_|\/social_share_|_social_share_|\.net\/adx\.php\?|\.ads2\-|\/ads2\.|\/ads2\/|\/ads2_|\/sharetools\/|\-img\/ads\/|\/img\-ads\.|\/img\-ads\/|\/img\.ads\.|\/img\/ads\/|\/images\/social_|\/admanager\/|\-dfp\-ads\/|\/dfp\-ads\.|\/dfp\-ads\/|\/assets\/twitter\-|\/assets\/js\/ad\.|\-search\-ads\.|\/search\-ads\?|\/search\/ads\?|\/search\/ads_|\/ad\/js\/pushdown\.|&adserver=|\-adserver\-|\-adserver\/|\.adserver\.|\/adserver\-|\/adserver\/|\/adserver\?|\/adserver_|\/images\/gplus\-|\/media\/ads\/|_media\/ads\/|\/img\/gplus_|\/images\.ads\.|\/images\/ads\-|\/images\/ads\.|\/images\/ads\/|\/images\/ads_|_images\/ads\/|\/adshow\-|\/adshow\.|\/adshow\/|\/adshow\?|\/adshow_|=adshow&|\/a\-ads\.|\.com\/counter\?|\/static\/ads\/|_static\/ads\/|\-ad\-banner\-|\-ad\-banner\.|\-ad_banner\-|\/ad\-banner\-|\/ad\-banner\.|\/ad\/banner\.|\/ad\/banner\/|\/ad\/banner\?|\/ad\/banner_|\/ad_banner\.|\/ad_banner\/|\/ad_banner_|\/2\/ads\/|\/head\-social\.|\/assets\/facebook\-|\/1\/ads\/|_mobile\/js\/ad\.|\-banner\-ad\-|\-banner\-ad\.|\-banner\-ad\/|\/banner\-ad\-|\/banner\-ad\.|\/banner\-ad\/|\/banner\-ad_|\/banner\/ad\.|\/banner\/ad\/|\/banner\/ad_|\/banner_ad\.|_banner\-ad\.|_banner_ad\-|_banner_ad\.|_banner_ad\/|\/wp\-content\/plugins\/automatic\-social\-locker\/|\-social\-media\.|\/social_media_|_social\-media_|\/tracker\/tracker\.js|\/img\/rss\.|\/img\/rss_|\/videoad\.|_videoad\.|\.sharecounter\.|&advertiserid=|\/cookie\-law\.js|\/cookie_law\.js|_cookie_law\.js|\/adworks\/|\/adwords\/|\/userad\/|_mainad\.|\/admax\/|_WebAd[^\w.%-]|\/product\-ad\/|\/social_bookmarking\/|\-ad0\.|\-social\-linked\-|_social_linked_|=advertiser\.|=advertiser\/|\?advertiser=|\/googlead\-|\/googlead\.|_googlead\.|\/adlink\?|\/adlink_|\/ad\-minister\-|\/cookies\-monster\.js|\/adfactory\-|\/adfactory_|\/adplayer\-|\/adplayer\/|\-adops\.|\/adops\/|\-google\-ads\-|\-google\-ads\/)/i;
var bad_url_parts_flag = 499 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_url_RegExp = /^$/;
var good_url_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var bad_url_RegExp = /^$/;
var bad_url_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules

// Add any good networks here. Format is network folowed by a comma and
// optional white space, and then the netmask.
// LAN, loopback, Apple (direct and Akamai e.g. e4805.a.akamaiedge.net), Microsoft (updates and services)
var GoodNetworks_Array = [ "10.0.0.0,     255.0.0.0" ];

// Apple iAd, Microsoft telemetry
var GoodNetworks_Exceptions_Array = [ "64.4.54.254,       255.255.255.255" ];

// Akamai: 23.64.0.0/14, 23.0.0.0/12, 23.32.0.0/11, 104.64.0.0/10

// Add any bad networks here. Format is network folowed by a comma and
// optional white space, and then the netmask.
// From securemecca.com: Adobe marketing cloud, 2o7, omtrdc, Sedo domain parking, flyingcroc, accretive
var BadNetworks_Array = [ "207.66.128.0,   255.255.128.0" ];

// block these schemes; use the command line for ftp, rsync, etc. instead
var bad_schemes_RegExp = RegExp("^(?:ftp|sftp|tftp|ftp-data|rsync|finger|gopher)", "i")

// RegExp for schemes; lengths from
// perl -lane 'BEGIN{$l=0;} {!/^#/ && do{$ll=length($F[0]); if($ll>$l){$l=$ll;}};} END{print $l;}' /etc/services
var schemepart_RegExp = RegExp("^([\\w*+-]{2,15}):\\/{0,2}","i");
var hostpart_RegExp = RegExp("^((?:[\\w-]+\\.)+[a-zA-Z0-9-]{2,24}\\.?)", "i");
var querypart_RegExp = RegExp("^((?:[\\w-]+\\.)+[a-zA-Z0-9-]{2,24}\\.?[\\w~%.\\/^*-]*)(\\??\\S*?)$", "i");
var domainpart_RegExp = RegExp("^(?:[\\w-]+\\.)*((?:[\\w-]+\\.)[a-zA-Z0-9-]{2,24})\\.?", "i");

//////////////////////////////////////////////////
// Define the is_ipv4_address function and vars //
//////////////////////////////////////////////////

var ipv4_RegExp = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function is_ipv4_address(host)
{
    var ipv4_pentary = host.match(ipv4_RegExp);
    var is_valid_ipv4 = false;

    if (ipv4_pentary) {
        is_valid_ipv4 = true;
        for( i = 1; i <= 4; i++) {
            if (ipv4_pentary[i] >= 256) {
                is_valid_ipv4 = false;
            }
        }
    }
    return is_valid_ipv4;
}

// object hashes
// Note: original stackoverflow-based hasOwnProperty does not woth within iOS kernel 
var hasOwnProperty = function(obj, prop) {
    return obj.hasOwnProperty(prop);
}

/////////////////////
// Done Setting Up //
/////////////////////

// debug with Chrome at chrome://net-internals/#events
// alert("Debugging message.")

//////////////////////////////////
// Define the FindProxyFunction //
//////////////////////////////////

var use_pass_rules_parts_flag = true;  // use the pass rules for url parts, then apply the block rules
var alert_flag = false;                // use for short-circuit '&&' to print debugging statements
var debug_flag = false;               // use for short-circuit '&&' to print debugging statements

// EasyList filtering for FindProxyForURL(url, host)
function EasyListFindProxyForURL(url, host)
{
    var host_is_ipv4 = is_ipv4_address(host);
    var host_ipv4_address;

    alert_flag && alert("url is: " + url);
    alert_flag && alert("host is: " + host);

    // Extract scheme and url without scheme
    var scheme = url.match(schemepart_RegExp)
    scheme = scheme.length > 0? scheme[1] : "";

    // Remove the scheme and extract the path for regex efficiency
    var url_noscheme = url.replace(schemepart_RegExp,"");
    var url_pathonly = url_noscheme.replace(hostpart_RegExp,"");
    var url_noquery = url_noscheme.replace(querypart_RegExp,"$1");
    // Remove the server name from the url and host if host is not an IPv4 address
    var url_noserver = !host_is_ipv4 ? url_noscheme.replace(domainpart_RegExp,"$1") : url_noscheme;
    var url_noservernoquery = !host_is_ipv4 ? url_noquery.replace(domainpart_RegExp,"$1") : url_noscheme;
    var host_noserver =  !host_is_ipv4 ? host.replace(domainpart_RegExp,"$1") : host;

    // Debugging results
    if (debug_flag && alert_flag) {
        alert("url_noscheme is: " + url_noscheme);
        alert("url_pathonly is: " + url_pathonly);
        alert("url_noquery is: " + url_noquery);
        alert("url_noserver is: " + url_noserver);
        alert("url_noservernoquery is: " + url_noservernoquery);
        alert("host_noserver is: " + host_noserver);
    }

    // Short circuit to blackhole for good_da_host_exceptions
    if ( hasOwnProperty(good_da_host_exceptions_JSON,host) ) {
        alert_flag && alert("good_da_host_exceptions_JSON blackhole!");
        return blackhole;
    }

    ///////////////////////////////////////////////////////////////////////
    // Check to make sure we can get an IPv4 address from the given host //
    // name.  If we cannot do that then skip the Networks tests.         //
    ///////////////////////////////////////////////////////////////////////

    host_ipv4_address = host_is_ipv4 ? host : (isResolvable(host) ? dnsResolve(host) : false);

    if (host_ipv4_address) {
        alert_flag && alert("host ipv4 address is: " + host_ipv4_address);
        /////////////////////////////////////////////////////////////////////////////
        // If the IP translates to one of the GoodNetworks_Array (with exceptions) //
        // we pass it because it is considered safe.                               //
        /////////////////////////////////////////////////////////////////////////////

        for (i in GoodNetworks_Exceptions_Array) {
            tmpNet = GoodNetworks_Exceptions_Array[i].split(/,\s*/);
            if (isInNet(host_ipv4_address, tmpNet[0], tmpNet[1])) {
                alert_flag && alert("GoodNetworks_Exceptions_Array Blackhole: " + host_ipv4_address);
                return blackhole;
            }
        }
        for (i in GoodNetworks_Array) {
            tmpNet = GoodNetworks_Array[i].split(/,\s*/);
            if (isInNet(host_ipv4_address, tmpNet[0], tmpNet[1])) {
                alert_flag && alert("GoodNetworks_Array PASS: " + host_ipv4_address);
                return proxy;
            }
        }

        ///////////////////////////////////////////////////////////////////////
        // If the IP translates to one of the BadNetworks_Array we fail it   //
        // because it is not considered safe.                                //
        ///////////////////////////////////////////////////////////////////////

        for (i in BadNetworks_Array) {
            tmpNet = BadNetworks_Array[i].split(/,\s*/);
            if (isInNet(host_ipv4_address, tmpNet[0], tmpNet[1])) {
                alert_flag && alert("BadNetworks_Array Blackhole: " + host_ipv4_address);
                return blackhole;
            }
        }
    }

    //////////////////////////////////////////////////////////////////////////////
    // HTTPS: https scheme can only use domain information                      //
    // unless PacHttpsUrlStrippingEnabled == false [Chrome] or                  //
    // network.proxy.autoconfig_url.include_path == true [firefox]              //
    // E.g. on macOS:                                                           //
    // defaults write com.google.Chrome PacHttpsUrlStrippingEnabled -bool false //
    // Check setting at page chrome://policy                                    //
    //////////////////////////////////////////////////////////////////////////////

    // Assume browser has disabled path access if scheme is https and path is '/'
    if ( scheme == "https" && url_pathonly == "/" ) {

        ///////////////////////////////////////////////////////////////////////
        // PASS LIST:   domains matched here will always be allowed.         //
        ///////////////////////////////////////////////////////////////////////

        if ( (good_da_host_exact_flag && (hasOwnProperty(good_da_host_JSON,host_noserver)||hasOwnProperty(good_da_host_JSON,host)))
            && !hasOwnProperty(good_da_host_exceptions_JSON,host) ) {
                alert_flag && alert("HTTPS PASS: " + host + ", " + host_noserver);
            return proxy;
        }

        //////////////////////////////////////////////////////////
        // BLOCK LIST:	stuff matched here here will be blocked //
        //////////////////////////////////////////////////////////

        if ( (bad_da_host_exact_flag && (hasOwnProperty(bad_da_host_JSON,host_noserver)||hasOwnProperty(bad_da_host_JSON,host))) ) {
            alert_flag && alert("HTTPS blackhole: " + host + ", " + host_noserver);
            return blackhole;
        }
    }

    ////////////////////////////////////////
    // HTTPS and HTTP: full path analysis //
    ////////////////////////////////////////

    if (scheme == "https" || scheme == "http") {

        ///////////////////////////////////////////////////////////////////////
        // PASS LIST:   domains matched here will always be allowed.         //
        ///////////////////////////////////////////////////////////////////////

        if ( !hasOwnProperty(good_da_host_exceptions_JSON,host)
            && ((good_da_host_exact_flag && (hasOwnProperty(good_da_host_JSON,host_noserver)||hasOwnProperty(good_da_host_JSON,host))) ||  // fastest test first
                (use_pass_rules_parts_flag &&
                    (good_da_hostpath_exact_flag && (hasOwnProperty(good_da_hostpath_JSON,url_noservernoquery)||hasOwnProperty(good_da_hostpath_JSON,url_noquery)) ) ||
                    // test logic: only do the slower test if the host has a (non)suspect fqdn
                    (good_da_host_regex_flag && (good_da_host_RegExp.test(host_noserver)||good_da_host_RegExp.test(host))) ||
                    (good_da_hostpath_regex_flag && (good_da_hostpath_RegExp.test(url_noservernoquery)||good_da_hostpath_RegExp.test(url_noquery))) ||
                    (good_da_regex_flag && (good_da_RegExp.test(url_noserver)||good_da_RegExp.test(url_noscheme))) ||
                    (good_url_parts_flag && good_url_parts_RegExp.test(url)) ||
                    (good_url_regex_flag && good_url_regex_RegExp.test(url)))) ) {
            return proxy;
        }

        //////////////////////////////////////////////////////////
        // BLOCK LIST:	stuff matched here here will be blocked //
        //////////////////////////////////////////////////////////
        // Debugging results
        if (debug_flag && alert_flag) {
            alert("hasOwnProperty(bad_da_host_JSON," + host_noserver + "): " + (bad_da_host_exact_flag && hasOwnProperty(bad_da_host_JSON,host_noserver)));
            alert("hasOwnProperty(bad_da_host_JSON," + host + "): " + (bad_da_host_exact_flag && hasOwnProperty(bad_da_host_JSON,host)));
            alert("hasOwnProperty(bad_da_hostpath_JSON," + url_noservernoquery + "): " + (bad_da_hostpath_exact_flag && hasOwnProperty(bad_da_hostpath_JSON,url_noservernoquery)));
            alert("hasOwnProperty(bad_da_hostpath_JSON," + url_noquery + "): " + (bad_da_hostpath_exact_flag && hasOwnProperty(bad_da_hostpath_JSON,url_noquery)));
            alert("bad_da_host_RegExp.test(" + host_noserver + "): " + (bad_da_host_regex_flag && bad_da_host_RegExp.test(host_noserver)));
            alert("bad_da_host_RegExp.test(" + host + "): " + (bad_da_host_regex_flag && bad_da_host_RegExp.test(host)));
            alert("bad_da_hostpath_RegExp.test(" + url_noservernoquery + "): " + (bad_da_hostpath_regex_flag && bad_da_hostpath_RegExp.test(url_noservernoquery)));
            alert("bad_da_hostpath_RegExp.test(" + url_noquery + "): " + (bad_da_hostpath_regex_flag && bad_da_hostpath_RegExp.test(url_noquery)));
            alert("bad_da_RegExp.test(" + url_noserver + "): " + (bad_da_regex_flag && bad_da_RegExp.test(url_noserver)));
            alert("bad_da_RegExp.test(" + url_noscheme + "): " + (bad_da_regex_flag && bad_da_RegExp.test(url_noscheme)));
            alert("bad_url_parts_RegExp.test(" + url + "): " + (bad_url_parts_flag && bad_url_parts_RegExp.test(url)));
            alert("bad_url_regex_RegExp.test(" + url + "): " + (bad_url_regex_flag && bad_url_regex_RegExp.test(url)));
        }

        if ( (bad_da_host_exact_flag && (hasOwnProperty(bad_da_host_JSON,host_noserver)||hasOwnProperty(bad_da_host_JSON,host))) ||  // fastest test first
            (bad_da_hostpath_exact_flag && (hasOwnProperty(bad_da_hostpath_JSON,url_noservernoquery)||hasOwnProperty(bad_da_hostpath_JSON,url_noquery)) ) ||
            // test logic: only do the slower test if the host has a (non)suspect fqdn
            (bad_da_host_regex_flag && (bad_da_host_RegExp.test(host_noserver)||bad_da_host_RegExp.test(host))) ||
            (bad_da_hostpath_regex_flag && (bad_da_hostpath_RegExp.test(url_noservernoquery)||bad_da_hostpath_RegExp.test(url_noquery))) ||
            (bad_da_regex_flag && (bad_da_RegExp.test(url_noserver)||bad_da_RegExp.test(url_noscheme))) ||
            (bad_url_parts_flag && bad_url_parts_RegExp.test(url)) ||
            (bad_url_regex_flag && bad_url_regex_RegExp.test(url)) ) {
            alert_flag && alert("Blackhole: " + url + ", " + host);
            return blackhole;
        }
    }

    // default pass
    alert_flag && alert("Default PASS: " + url + ", " + host);
    return proxy;
}

// User-supplied FindProxyForURL()
function FindProxyForURL(url, host)
{
if (
   isPlainHostName(host) ||
   shExpMatch(host, "10.*") ||
   shExpMatch(host, "172.16.*") ||
   shExpMatch(host, "192.168.*") ||
   shExpMatch(host, "127.*") ||
   dnsDomainIs(host, ".LOCAL") ||
   dnsDomainIs(host, ".local") ||
   (url.substring(0,4) == "ftp:")
)
        return "DIRECT";
else
        return EasyListFindProxyForURL(url, host);
}
