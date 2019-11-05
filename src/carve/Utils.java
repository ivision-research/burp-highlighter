/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package carve;

/**
 *
 * @author asuarez
 */
public class Utils
{
    	private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

	public static String bytesToHexString(byte[] bs) {
		char[] hex = new char[bs.length * 2];
		for (int i = 0; i < bs.length; i++) {
			int bv = bs[i] & 0xFF;
			hex[i << 1] = HEX_CHARS[bv >> 4];
			hex[(i << 1) + 1] = HEX_CHARS[bv & 0xF];
		}
		return new String(hex);
	}
}
