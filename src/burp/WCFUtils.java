/*
 * Copyright (c) John Murray, 2015.
 *
 *   This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU Affero General Public License as
 *     published by the Free Software Foundation, either version 3 of the
 *     License, or (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU Affero General Public License for more details.
 *
 *     You should have received a copy of the GNU Affero General Public License
 *     along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package burp;

import sun.security.provider.Sun;

import java.io.BufferedReader;
import java.io.Console;
import java.io.InputStreamReader;
import java.util.List;
import java.util.zip.GZIPInputStream;
import java.io.ByteArrayInputStream;

public class WCFUtils
{
	public static String WCFHeader = "msbin";
	public static String SERIALIZEHEADER = "Via:WCFSERIALIZED-GOODNESS";

	public static byte[] toXML(byte[] message, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers)
	{
		try
		{
			List<String> headers = helpers.analyzeRequest(message).getHeaders();
			int bodyOffset = helpers.analyzeRequest(message).getBodyOffset();
			byte[] body = new byte[message.length - bodyOffset];

			//copy it and convert it to XML
			System.arraycopy(message, bodyOffset, body, 0, message.length - bodyOffset);
			
			String xml = encodeDecodeWcf(true, helpers.bytesToString(body), callbacks, helpers);
			byte[] decoded = helpers.base64Decode(xml);

			return helpers.buildHttpMessage(headers, decoded);
		}
		catch (Exception e)
		{
			e.printStackTrace();
			return message;
		}
	}

	public static byte[] fromXML(byte[] xml, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers)
	{
		try
		{
			byte[] decoded = helpers.base64Decode(encodeDecodeWcf(false, helpers.bytesToString(xml), callbacks, helpers));
			return  decoded;
		}
		catch (Exception ex)
		{
			System.out.println("Error deserializing XML " + ex.getMessage());
			return null;
		}
	}

	public static String encodeDecodeWcf(boolean isBinary, String content, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers)
	{
		try
		{
			String strBase64Content = helpers.base64Encode(content);
			String strEncodeDecode = isBinary == true ? "DECODE" : "ENCODE";
			
			if (isBinary)
			{
				String out = "";
				byte[] binaryinput = helpers.stringToBytes(content);
				if (binaryinput[0] == 0x1f && binaryinput[1] == 0x8b && binaryinput[2] == 0x08)
				{
					GZIPInputStream gzis = new GZIPInputStream(new ByteArrayInputStream(binaryinput));
					byte[] buffer = new byte[1024];
					int len;
					while((len = gzis.read(buffer)) != -1)
					{
						byte[] temp = new byte[len];
						System.arraycopy(buffer, 0, temp, 0, len);
						out += helpers.bytesToString(temp);
					}
					strBase64Content = helpers.base64Encode(out);
				}
			}

			String line;
			String out;
			String[] commandWithArgs = { "dotnet", "NBFS.dll" , strEncodeDecode, strBase64Content };
			Process p = Runtime.getRuntime().exec(commandWithArgs);
			BufferedReader input = new BufferedReader(new InputStreamReader(p.getInputStream()));
			if ((line = input.readLine()) != null)
				out = line;
			else
				out = "An Error Has Occurred";
			input.close();
			return out;
		}
		catch (Exception err)
		{
			return err.getMessage();
		}
	}

	public static boolean isWCF(byte[] content, IExtensionHelpers helpers)
	{
		return (helpers.indexOf(content, helpers.stringToBytes(WCFUtils.WCFHeader), false, 0, content.length) > -1);
	}

	public static boolean hasMagicHeader(byte[] content, IExtensionHelpers helpers)
	{
		return helpers.indexOf(content, helpers.stringToBytes(WCFUtils.SERIALIZEHEADER), false, 0, content.length) > -1;
	}
}
