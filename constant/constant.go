/**
 * @Time    :2023/6/20 11:01
 * @Author  :Xiaoyu.Zhang
 */

package smconstant

type EncryptMode int

const (
	CBC EncryptMode = iota // 密码分组链接模式
	ECB                    // 电码本模式
	CTR                    // 计算器模式
	OFB                    // 输出反馈模式
	CFB                    // 密码反馈模式
	GCM                    // Galois/Counter Mode
)
