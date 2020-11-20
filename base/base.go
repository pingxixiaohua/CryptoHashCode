package base

import "encoding/base64"

/*
 * base64 编码
 */
func Base64Encode(data []byte) []byte {
	/*
	 *	base64:  64个字符，A - Z, a - z, 0 - 9, +, ?
	 *	3 * 8 = 24
	 *	4 * 6 = 24 ,四组
	 *	分组后每一组6位： 11111 -> 63 、 000000 -> 0
	 * 	一共64：
	 *	原理：
	 *		1、数据 -> ASCII编码（十进制）
	 *		2、十进制 -> 二进制（0和1的组合）
	 *		3、6位一组进行分组
	 *		4、将6位一组的二进制转换十进制 （范围0-63）
	 *		5、将转后十进制数作为元素的下标到固定的编码表中获取对应位置的元素
	 *
	 *		将原数据进行24位一组分组， 分组情况有三种：
	 *			1、刚刚满足24位一组的分组，恰好
	 *			2、余数为1个字符，最后补两个=
	 *			3、余数为2个字符，最后补一个=
	 */
	//encoding := base64.NewEncoding()

	encoding := base64.StdEncoding
	dst := make([]byte, encoding.EncodedLen(len(data)))
	encoding.Encode(dst,data)
	return dst

}

func Base64Decode(data string) []byte {

	encoding := base64.StdEncoding
	dst := make([]byte,encoding.DecodedLen(len(data)))
	n, _ := encoding.Decode(dst, []byte(data))
	return dst[0:n]
}
