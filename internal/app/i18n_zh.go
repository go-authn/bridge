// SPDX-License-Identifier: BSD-3-Clause

package app

// catZH is Simplified Chinese. Written without a native review: corrections
// are welcome.
var catZH = map[string]string{
	"skip": "跳到正文",
	"help": "帮助",

	"lang.nav": "语言",
	"lang.go":  "应用",

	"theme.nav":    "切换主题",
	"theme.light":  "浅色",
	"theme.dark":   "深色",
	"theme.system": "跟随系统",

	"js.unsupported": "此浏览器不支持通行密钥。",
	"js.invite":      "请打开完整的邀请链接。",
	"js.cancelled":   "已取消，或已超时。",
	"js.exists":      "此设备已有该账户的通行密钥。",
	"js.failed":      "失败：%s",
	"js.registered":  "通行密钥已注册。您可以关闭此页面。",
	"js.waiting":     "正在等待您的设备…",

	"msg.title": "登录",

	"choose.title":  "请选择您所属的机构",
	"choose.ttl":    "选择机构",
	"choose.q":      "名称或域名",
	"choose.search": "搜索",
	"choose.none":   "没有匹配的机构。",
	"choose.more":   "还有 %d 个：请缩小搜索范围。",

	"method.title":     "登录",
	"method.fed":       "使用所属机构账户",
	"method.fed.sub":   "您的工作或大学账户。",
	"method.local":     "使用本地账户",
	"method.local.sub": "通过邀请创建的通行密钥。",

	"login.title":  "本地账户",
	"login.button": "使用通行密钥登录",
	"login.manage": "管理我的通行密钥",

	"nojs.passkey": "通行密钥需要 JavaScript。",
	"nojs.page":    "此页面需要 JavaScript。",

	"enroll.title":  "注册通行密钥",
	"enroll.p":      "管理员已向您发出邀请。您的设备将提示您创建通行密钥并解锁（指纹、面容或 PIN 码）。",
	"enroll.button": "创建我的通行密钥",

	"device.title":    "连接设备",
	"device.code":     "设备上显示的代码",
	"device.err.rate": "尝试次数过多，请几分钟后再试。",
	"device.err.code": "此代码无效或已过期。",
	"continue":        "继续",

	"confirm.ttl":    "确认",
	"confirm.title":  "%s 请求以您的名义登录",
	"confirm.code":   "代码",
	"h.confirm.warn": "<strong>只有当此次登录是您本人在自己的设备上发起时才继续。</strong>如果有人把这个代码发给您，请拒绝：对方将代替您获得访问权限。",
	"confirm.yes":    "是的，是我本人",
	"confirm.no":     "否",

	"open.wait": "请稍候…",

	"acct.title":      "我的账户",
	"acct.done":       "完成",
	"acct.identity":   "身份信息",
	"acct.login":      "登录名",
	"acct.name":       "姓名",
	"acct.mail":       "电子邮件",
	"acct.groups":     "组",
	"acct.source":     "来源",
	"acct.src":        "本地账户",
	"acct.note.local": "电子邮件和组由服务管理员修改，不能在此处修改。",
	"acct.note.fed":   "电子邮件和组由您所属的机构修改，不能在此处修改。",
	"acct.dispname":   "显示名称",
	"save":            "保存",

	"keys.title":    "通行密钥",
	"keys.sub":      "每台设备保存各自的密钥：请删除已丢失设备的密钥。",
	"keys.created":  "创建于",
	"keys.lastused": "上次使用",
	"keys.never":    "从未使用",
	"keys.backup":   "可同步",
	"keys.current":  "本次确认所用的密钥",
	"keys.confirm":  "删除此通行密钥？",
	"keys.full":     "每个账户最多 %d 个通行密钥：请先删除一个再添加。",
	"keys.add":      "添加通行密钥",
	"remove":        "删除",

	"apps.title":      "应用与会话",
	"apps.opened":     "开始于",
	"apps.never":      "从未续期",
	"apps.none":       "无。",
	"apps.confirm":    "结束此会话？",
	"apps.revokeall":  "全部撤销",
	"apps.confirmall": "结束所有会话？",
	"revoke":          "撤销",

	"access.kind.app_password": "应用密码",
	"access.kind.ssh":          "SSH 证书",
	"access.kind.x509":         "X.509 证书",
	"access.kind.wireguard":    "WireGuard 密钥",
	"access.title":             "技术访问",
	"access.expires":           "到期",
	"access.none":              "无。",
	"access.confirm":           "撤销此访问权限？",

	"step.done.title": "会话已结束",
	"step.done.p":     "您的账户空间已关闭。您可以关闭此页面，或重新登录。",
	"step.p":          "请确认是您本人：确认的有效期为五分钟。",
	"step.passkey":    "使用我的通行密钥确认",
	"step.fed":        "使用所属机构确认",

	"ph.summary":   "通行密钥帮助",
	"ph.what.h":    "什么是通行密钥？",
	"ph.what.p":    "通行密钥让您无需输入任何内容即可登录：设备会用您的指纹、面容或 PIN 码将其解锁。它不会离开设备，并且只能用于此服务。",
	"ph.dev.h":     "手机、电脑或安全密钥",
	"h.ph.dev.1":   "<strong>电脑或手机：</strong>用设备的指纹、面容或 PIN 码确认。如果通行密钥在您的手机上，请在浏览器弹出的窗口中选择“手机”，然后扫描二维码。",
	"h.ph.dev.2":   "<strong>安全密钥（USB、NFC）：</strong>插入后，在浏览器提示时<strong>触摸密钥</strong>。如果设置了 PIN 码，系统会要求输入。",
	"ph.fail.h":    "如果被拒绝",
	"ph.fail.1":    "“已取消”或“已超时”：请重试，并及时响应设备的提示。",
	"ph.fail.2":    "解锁设备，插入或靠近密钥；使用手机时请打开蓝牙。",
	"ph.fail.3":    "请尝试其他最新版本的浏览器，或创建该通行密钥的设备。",
	"ph.fail.pre":  "仍然无法解决？",
	"ph.support":   "请联系支持团队",
	"ph.admin":     "请联系服务管理员",
	"ph.fail.post": "以获取新的邀请。",
}
