package burp;

import com.sun.org.apache.xpath.internal.functions.FuncFalse;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import java.util.ArrayList;
import java.io.PrintWriter;
import java.util.List;
import javax.swing.JMenuItem;
import java.util.Arrays;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.GZIPOutputStream;

public class BurpExtender implements IBurpExtender, IHttpListener {

	private IBurpExtenderCallbacks callbacks;
	private static String[] colorArray = new String[]{"red", "orange", "yellow", "green", "cyan", "blue", "pink", "magenta", "gray"};
	private static IMessageEditorTab HaETab;
	private static PrintWriter stdout;
	private static boolean isEnable = true;
	IExtensionHelpers helpers = null;


	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		this.helpers = callbacks.getHelpers();

		// 设置插件名字
		callbacks.setExtensionName("BurpSuite Auto Do Intercept");

		// 定义输出
		stdout = new PrintWriter(callbacks.getStdout(), true);
		stdout.println("Author: xiaoxiaoleo");
		stdout.println("Repo: https://github.com/xiaoxiaoleo/Burp-Auto-Do-Intercept");

		callbacks.registerHttpListener(BurpExtender.this);
	}


	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		if (messageIsRequest == true) {
			String headerName = "browser-color:";
			String hColor = "red";

	/*		IRequestInfo rqInfo = helpers.analyzeRequest(proxyMessage.getMessageInfo());
			// retrieve all headers
			ArrayList<String> headers = (ArrayList<String>) rqInfo.getHeaders();
			String lineOne = headers.get(0);


			String path = lineOne.split(" ")[1];
			String method = lineOne.split(" ")[0];

			if (path == "/api/pull/assist-list") {
				proxyMessage.getMessageInfo().setHighlight(hColor);
			}
*/

		} else {

			IResponseInfo analyzedResponse = helpers.analyzeResponse(messageInfo.getResponse()); //getResponse获得的是字节序列
			short statusCode = analyzedResponse.getStatusCode();
			List<String> headers = analyzedResponse.getHeaders();
			String resp = new String(messageInfo.getResponse());
			int bodyOffset = analyzedResponse.getBodyOffset();//响应包是没有参数的概念的，大多需要修改的内容都在body中
			String body = resp.substring(bodyOffset);

			int flag = 2;

			switch (flag) {
				case 1://处理header，如果这里修改了response,注意case2中应该从新获取header内容。
					break;
				case 2://处理body
					if (statusCode==200){
						try{
							String newBody = "{\"errcode\":0,\"data\":{\"assist_num\": 100}}\n";
							byte[] bodybyte = newBody.getBytes();
							messageInfo.setResponse(helpers.buildHttpMessage(headers, bodybyte));
						}catch(Exception e){
							callbacks.printError(e.getMessage());
						}
					}
					break;
				default:
					break;
			}
		}


	}

}