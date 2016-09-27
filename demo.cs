using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Security;

namespace ConsoleApplication4
{
   public class YzjAuth1
    {
        private static readonly String HOST = "https://www.yunzhijia.com/";
        private static String appTokenURL = HOST + "openapi/third/v1/newtodo/open/action.json";
        private static int connTimeout = 5000;
        private static int readTimeout = 5000;
        private static String METHON = "POST";
        /// <summary>
        /// 得到授权
        /// </summary>
        /// <param name="consumerKey"></param>
        /// <param name="consumerSecret"></param>
        /// <returns></returns>
        public static String getOauthToken(String consumerKey,
            String consumerSecret)
        {
            OAuth oAuth = new OAuth(consumerKey, consumerSecret, "");
            String authorization = oAuth.generateAuthorizationHeader(METHON,
                    appTokenURL, null, null);
            return authorization;

        }
    }

   public class OAuth
   {
       private static readonly String HMAC_SHA1 = "HmacSHA1";
       static readonly long serialVersionUID = -4368426677157998618L;
       private String consumerKey { get; set; }

       private String consumerSecret { get; set; }

       private String oauthVerifier { get; set; }

       private static Random RAND = new Random();
       public OAuth(String consumerKey, String consumerSecret, String oauthVerifier)
       {
           this.consumerKey = consumerKey;
           this.consumerSecret = consumerSecret;
           if (string.IsNullOrEmpty(oauthVerifier))
           {
               this.oauthVerifier = oauthVerifier;
           }
       }

       /// <summary>
       /// 设置授权头
       /// </summary>
       /// <param name="method"></param>
       /// <param name="url"></param>
       /// <param name="?"></param>
       /// <returns></returns>
       public String generateAuthorizationHeader(String method, String url, object o, OAuthToken token)
       {
           string timestamp = (System.DateTime.Now).ToString();
           string nonce = (System.DateTime.Now.ToString() + new Random().Next()).ToString();
           return generateAuthorizationHeader(method, url, null,
               nonce, timestamp, token);
       }

       ////字典
       //private Dictionary<string, string> signatureBaseParams = new Dictionary<string, string>();
       ////排序字典
       //private Dictionary<string, string> sortsignatureBaseParams = new Dictionary<string, string>();
       private String generateAuthorizationHeader(string method, string url, object o, string nonce,
           string timestamp, OAuthToken otoken)
       {

           long timestamp1 =
               ((long) (DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds)/1000L;
           long nonce1 = timestamp1 + RAND.Next();
           //Dictionary<string, string> dcbase = new Dictionary<string, string>();
           //字典
           Dictionary<string, string> signatureBaseParams = new Dictionary<string, string>();
           //排序字典
           Dictionary<string, string> sortsignatureBaseParams = new Dictionary<string, string>();
           signatureBaseParams.Add("oauth_consumer_key", this.consumerKey);
           signatureBaseParams.Add("oauth_nonce", nonce1.ToString());
           signatureBaseParams.Add("oauth_signature_method", "HMAC-SHA1");
           signatureBaseParams.Add("oauth_timestamp", timestamp1.ToString());
           signatureBaseParams.Add("oauth_version", "1.0");

           //foreach (string key in dcbase.Keys)
           //{
           //    signatureBaseParams.Add(key, dcbase[key]);
           //}
           //新添参数没弄
           ParePara(url, signatureBaseParams);

           signatureBaseParams = signatureBaseParams.OrderBy(m => m.Key).ToDictionary(m => m.Key, p => p.Value);

           StringBuilder base1 = new StringBuilder(method).Append("&")
               .Append(encode(constructRequestURL(url))).Append(("&"));
           string encostr = encode(normalizeRequestParameters(signatureBaseParams));
           base1.Append(encostr);
           String oauthBaseString = base1.ToString();
           //oauthBaseString =
           //    "POST&https%3A%2F%2Fwww.yunzhijia.com%2Fopenapi%2Fthird%2Fv1%2Fopendata-control%2Fdata%2Fgetperson&eid%3D4491460%26oauth_consumer_key%3D10231%26" +
           //    "oauth_nonce%3D3283982167%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1469524742%26oauth_version%3D1.0%26openId%3D5746daa0e4b00f589d350f2f";
           String signature = generateSignature(oauthBaseString, otoken);

           

           sortsignatureBaseParams.Add("oauth_consumer_key", this.consumerKey);

           sortsignatureBaseParams.Add("oauth_signature_method", "HMAC-SHA1");
           sortsignatureBaseParams.Add("oauth_timestamp", timestamp1.ToString());
           sortsignatureBaseParams.Add("oauth_nonce", nonce1.ToString());
           sortsignatureBaseParams.Add("oauth_version", "1.0");
           sortsignatureBaseParams.Add("oauth_signature", signature);
           string OAuthStr = "OAuth " + encodeParameters(sortsignatureBaseParams.ToList(), ",", true);
           return OAuthStr;
       }

       public string generateAuthorizationHeader1()
       {

           long timestamp1 = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds;              
           long nonce1 = timestamp1 + RAND.Next();
           //字典
           Dictionary<string, string> signatureBaseParams = new Dictionary<string, string>();
           //排序字典
           Dictionary<string, string> sortsignatureBaseParams = new Dictionary<string, string>();
           signatureBaseParams.Add("appid", this.consumerKey);
           signatureBaseParams.Add("nonce", nonce1.ToString());
           signatureBaseParams.Add("timestamp", timestamp1.ToString());
           signatureBaseParams.Add("version", "1.1");
           signatureBaseParams.Add("appSecret", this.consumerSecret);
           signatureBaseParams = signatureBaseParams.OrderBy(m => m.Value).ToDictionary(m => m.Key, p => p.Value);
           string data = string.Empty;
           foreach (var key in signatureBaseParams.Keys)
           {
               data += signatureBaseParams[key];
           }           
           data = SHA1_To(data);
           string authorization = "OpenAuth2 version={0}, appid={1}, timestamp={2}, nonce={3}, sign={4}";           
           return string.Format(authorization, "1.1", this.consumerKey, timestamp1.ToString(), nonce1.ToString(), data);
       }

       public string EncryptToSHA1(string str)
       {
           return FormsAuthentication.HashPasswordForStoringInConfigFile(str, "SHA1");
       }

       public string SHA1_To(string str)
       {
           byte[] StrRes = Encoding.Default.GetBytes(str);
           HashAlgorithm iSHA = new SHA1CryptoServiceProvider();
           StrRes = iSHA.ComputeHash(StrRes);
           StringBuilder EnText = new StringBuilder();
           foreach (byte iByte in StrRes)
           {
               EnText.AppendFormat("{0:x2}", iByte);
           }
           return EnText.ToString();
       }
       static public string SHA1_Hash(string str)
       {
           SHA1CryptoServiceProvider sha1 = new SHA1CryptoServiceProvider();
           byte[] str1 = Encoding.UTF8.GetBytes(str);
           byte[] str2 = sha1.ComputeHash(str1);
           sha1.Clear();
           (sha1 as IDisposable).Dispose();
           return Convert.ToBase64String(str2);
       }
       protected String generateSignature(String data, OAuthToken token)
       {
           HMACSHA1 hmacsha1 = new HMACSHA1();
           hmacsha1.Key = Encoding.UTF8.GetBytes(this.consumerSecret + "&");
           byte[] dataBuffer = Encoding.UTF8.GetBytes(data);
           byte[] hashBytes = hmacsha1.ComputeHash(dataBuffer);
           return Convert.ToBase64String(hashBytes);

       }
       public static String normalizeRequestParameters(Dictionary<string, string> dcparas)
       {
           // dcparas.ToList().Sort();

           return encodeParameters(dcparas.ToList());
       }
       public static String encodeParameters(List<KeyValuePair<string, string>> o)
       {
           return encodeParameters(o, "&", false);
       }
       public static String encodeParameters(List<KeyValuePair<string, string>> o, String splitter, Boolean quot)
       {
           StringBuilder buf = new StringBuilder();
           foreach (KeyValuePair<string, string> pa in o)
           {
               if (buf.Length != 0)
               {
                   if (quot)
                   {
                       buf.Append("\"");
                   }
                   buf.Append(splitter);
               }
               buf.Append(encode(pa.Key)).Append("=");
               if (quot)
               {
                   buf.Append("\"");
               }
               buf.Append(encode(pa.Value));
           }
           if ((buf.Length != 0) &&
             (quot))
           {
               buf.Append("\"");
           }

           return buf.ToString();
       }
       /// <summary>
       /// 构造请求url
       /// </summary>
       /// <param name="url"></param>
       /// <returns></returns>
       public static String constructRequestURL(String url)
       {
           int index = url.IndexOf("?");
           if (-1 != index)
           {
               url = url.Substring(0, index);
           }
           int slashIndex = url.IndexOf("/", 8);
           String baseURL = url.Substring(0, slashIndex).ToLower();
           int colonIndex = baseURL.IndexOf(":", 8);
           if (-1 != colonIndex)
           {
               if ((baseURL.StartsWith("http://")) && (baseURL.EndsWith(":80")))
               {
                   baseURL = baseURL.Substring(0, colonIndex);
               }
               else if ((baseURL.StartsWith("https://")) &&
                 (baseURL.EndsWith(":443")))
               {
                   baseURL = baseURL.Substring(0, colonIndex);
               }
           }
           url = baseURL + url.Substring(slashIndex);
           return url;
       }
       /// <summary>
       /// 解决javaC#转码区别 java转码为小写 C#为大写
       /// </summary>
       /// <param name="temp"></param>
       /// <param name="encoding"></param>
       /// <returns></returns>
       private static string UrlEncode(string temp, Encoding encoding)
       {
           StringBuilder stringBuilder = new StringBuilder();
           for (int i = 0; i < temp.Length; i++)
           {
               string t = temp[i].ToString();
               string k = HttpUtility.UrlEncode(t, encoding);
               if (t == k)
               {
                   stringBuilder.Append(t);
               }
               else
               {
                   stringBuilder.Append(k.ToUpper());
               }
           }
           return stringBuilder.ToString();
       }
       /// <summary>
       /// 解码
       /// </summary>
       /// <param name="value"></param>
       /// <returns></returns>
       public static String encode(String value)
       {
           String encoded = null;

           //encoded = System.Web.HttpUtility.UrlEncode(value, System.Text.Encoding.UTF8);
           encoded = UrlEncode(value, System.Text.Encoding.UTF8);
           StringBuilder buf = new StringBuilder(encoded.Length);

           for (int i = 0; i < encoded.Length; i++)
           {
               char focus = encoded.ElementAt(i);
               if (focus == '*')
               {
                   buf.Append("%2A");
               }
               else if (focus == '+')
               {
                   buf.Append("%20");
               }
               else if ((focus == '%') && (i + 1 < encoded.Length) &&
               (encoded.ElementAt(i + 1) == '7') &&
               (encoded.ElementAt(i + 2) == 'E'))
               {
                   buf.Append('~');
                   i += 2;
               }
               else
               {
                   buf.Append(focus);
               }
           }
           return buf.ToString();

       }

       private
           void ParePara(String url, Dictionary<string, string> signatureBaseParams)
       {
           int queryStart = url.IndexOf("?", StringComparison.Ordinal);
           if (-1 != queryStart)
           {
               string[] queryStrs = url.Substring(queryStart + 1).Split('&');//分割参数与请求部分参数
               foreach (string query in queryStrs)
               {
                   string[] split = query.Split('=');
                   if (split.Length == 2)
                   {
                       string a = System.Web.HttpUtility.UrlDecode(split[0], System.Text.Encoding.UTF8);
                       string b = System.Web.HttpUtility.UrlDecode(split[1], System.Text.Encoding.UTF8);
                       signatureBaseParams.Add(a, b);
                   }
                   else
                   {
                       string a1 = System.Web.HttpUtility.UrlDecode(split[0], System.Text.Encoding.UTF8);

                       signatureBaseParams.Add(a1, "");
                   }
               }

           }
       }
   }
   public class OAuthToken
   {

   }
   /// <summary>
   /// Base64编码类。
   /// 将byte[]类型转换成Base64编码的string类型。
   /// </summary>
   public class Base64Encoder
   {
       byte[] source;
       int length, length2;
       int blockCount;
       int paddingCount;
       public static Base64Encoder Encoder = new Base64Encoder();

       public Base64Encoder()
       {
       }

       private void init(byte[] input)
       {
           source = input;
           length = input.Length;
           if ((length % 3) == 0)
           {
               paddingCount = 0;
               blockCount = length / 3;
           }
           else
           {
               paddingCount = 3 - (length % 3);
               blockCount = (length + paddingCount) / 3;
           }
           length2 = length + paddingCount;
       }

       public string GetEncoded(byte[] input)
       {
           //初始化
           init(input);

           byte[] source2;
           source2 = new byte[length2];

           for (int x = 0; x < length2; x++)
           {
               if (x < length)
               {
                   source2[x] = source[x];
               }
               else
               {
                   source2[x] = 0;
               }
           }

           byte b1, b2, b3;
           byte temp, temp1, temp2, temp3, temp4;
           byte[] buffer = new byte[blockCount * 4];
           char[] result = new char[blockCount * 4];
           for (int x = 0; x < blockCount; x++)
           {
               b1 = source2[x * 3];
               b2 = source2[x * 3 + 1];
               b3 = source2[x * 3 + 2];

               temp1 = (byte)((b1 & 252) >> 2);

               temp = (byte)((b1 & 3) << 4);
               temp2 = (byte)((b2 & 240) >> 4);
               temp2 += temp;

               temp = (byte)((b2 & 15) << 2);
               temp3 = (byte)((b3 & 192) >> 6);
               temp3 += temp;

               temp4 = (byte)(b3 & 63);

               buffer[x * 4] = temp1;
               buffer[x * 4 + 1] = temp2;
               buffer[x * 4 + 2] = temp3;
               buffer[x * 4 + 3] = temp4;

           }

           for (int x = 0; x < blockCount * 4; x++)
           {
               result[x] = sixbit2char(buffer[x]);
           }


           switch (paddingCount)
           {
               case 0: break;
               case 1: result[blockCount * 4 - 1] = '='; break;
               case 2: result[blockCount * 4 - 1] = '=';
                   result[blockCount * 4 - 2] = '=';
                   break;
               default: break;
           }
           return new string(result);
       }
       private char sixbit2char(byte b)
       {
           char[] lookupTable = new char[64]{
'A','B','C','D','E','F','G','H','I','J','K','L','M',
'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
'a','b','c','d','e','f','g','h','i','j','k','l','m',
'n','o','p','q','r','s','t','u','v','w','x','y','z',
'0','1','2','3','4','5','6','7','8','9','+','/'};

           if ((b >= 0) && (b <= 63))
           {
               return lookupTable[(int)b];
           }
           else
           {

               return ' ';
           }
       }

   }
   /// <summary>
   /// Base64解码类
   /// 将Base64编码的string类型转换成byte[]类型
   /// </summary>
   public class Base64Decoder
   {
       char[] source;
       int length, length2, length3;
       int blockCount;
       int paddingCount;
       public static Base64Decoder Decoder = new Base64Decoder();

       public Base64Decoder()
       {
       }

       private void init(char[] input)
       {
           int temp = 0;
           source = input;
           length = input.Length;

           for (int x = 0; x < 2; x++)
           {
               if (input[length - x - 1] == '=')
                   temp++;
           }
           paddingCount = temp;

           blockCount = length / 4;
           length2 = blockCount * 3;
       }

       public byte[] GetDecoded(string strInput)
       {
           //初始化
           init(strInput.ToCharArray());

           byte[] buffer = new byte[length];
           byte[] buffer2 = new byte[length2];

           for (int x = 0; x < length; x++)
           {
               buffer[x] = char2sixbit(source[x]);
           }

           byte b, b1, b2, b3;
           byte temp1, temp2, temp3, temp4;

           for (int x = 0; x < blockCount; x++)
           {
               temp1 = buffer[x * 4];
               temp2 = buffer[x * 4 + 1];
               temp3 = buffer[x * 4 + 2];
               temp4 = buffer[x * 4 + 3];

               b = (byte)(temp1 << 2);
               b1 = (byte)((temp2 & 48) >> 4);
               b1 += b;

               b = (byte)((temp2 & 15) << 4);
               b2 = (byte)((temp3 & 60) >> 2);
               b2 += b;

               b = (byte)((temp3 & 3) << 6);
               b3 = temp4;
               b3 += b;

               buffer2[x * 3] = b1;
               buffer2[x * 3 + 1] = b2;
               buffer2[x * 3 + 2] = b3;
           }

           length3 = length2 - paddingCount;
           byte[] result = new byte[length3];

           for (int x = 0; x < length3; x++)
           {
               result[x] = buffer2[x];
           }

           return result;
       }

       private byte char2sixbit(char c)
       {
           char[] lookupTable = new char[64]{ 
'A','B','C','D','E','F','G','H','I','J','K','L','M','N',
'O','P','Q','R','S','T','U','V','W','X','Y', 'Z',
'a','b','c','d','e','f','g','h','i','j','k','l','m','n',
'o','p','q','r','s','t','u','v','w','x','y','z',
'0','1','2','3','4','5','6','7','8','9','+','/'};
           if (c == '=')
               return 0;
           else
           {
               for (int x = 0; x < 64; x++)
               {
                   if (lookupTable[x] == c)
                       return (byte)x;
               }

               return 0;
           }

       }
   }
   public class DaiBanAction
   {
       /// <summary>
       /// Read
       /// </summary>
       public int read { get; set; }
       /// <summary>
       /// Deal
       /// </summary>
       public int deal { get; set; }
       /// <summary>
       /// Delete
       /// </summary>
       public int delete { get; set; }
   }

   public class DaiBanJson
   {
       /// <summary>
       /// Sourcetype
       /// </summary>
       public string sourcetype { get; set; }
       /// <summary>
       /// Sourceitemid
       /// </summary>
       public string sourceitemid { get; set; }
       /// <summary>
       /// Openids
       /// </summary>
       public List<string> openids { get; set; }
       /// <summary>
       /// Actiontype
       /// </summary>
       public DaiBanAction actiontype { get; set; }
   }
}
