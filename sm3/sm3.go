/**
 * @Time    :2022/5/14 8:17
 * @Author  :MELF晓宇
 * @Email   :xyzh.melf@petalmail.com
 * @FileName:sm3.go
 * @Project :gin-start
 * @Blog    :https://blog.csdn.net/qq_29537269
 * @Guide   :https://guide.melf.space
 * @Information:
 *
 */

package sm3

import (
	"fmt"
	"github.com/tjfoc/gmsm/sm3"
)

// Hash
/**
 * @Description: Hash(可用此方法代替MD5算法)
 * @param data
 * @return sign
 */
func Hash(data string) (sign string) {
	h := sm3.New()
	h.Write([]byte(data))
	sum := h.Sum(nil)
	return fmt.Sprintf("%x", sum)
}
