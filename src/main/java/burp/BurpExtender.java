package burp;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.*;

import javax.swing.*;

import javax.swing.table.DefaultTableModel;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;


import java.awt.Component;
import java.io.PrintWriter;
import java.net.URLDecoder;

import com.alibaba.fastjson.JSON;

import custom.util.CCombinationConfig;
import custom.util.IHttpReqRespUtil;
import custom.view.CGUI;
import custom.util.CHttpReqRespUtil;



public class BurpExtender implements IBurpExtender, IHttpListener, ITab, IContextMenuFactory
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;//现在这里定义变量，再在registerExtenderCallbacks函数中实例化，如果都在函数中就只是局部变量，不能在这实例化，因为要用到其他参数。
	private CGUI frame = new CGUI();

	public String extenderName = "Resign Plus v2.0 by R4ph4e1";





	// implement IBurpExtender
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {//当加载插件的时候，会调用下面的方法。
    	stdout = new PrintWriter(callbacks.getStdout(), true);
    	//PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true); 这种写法是定义变量和实例化，这里的变量就是新的变量而不是之前class中的全局变量了。
    	stdout.println(extenderName+" | Modified from Resign v2.2(Original author: bit4woo)\r\n");
    	//System.out.println("test"); 不会输出到burp的
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName(extenderName); //插件名称
        callbacks.registerHttpListener(this); //如果没有注册，下面的processHttpMessage方法是不会生效的。处理请求和响应包的插件，这个应该是必要的
        callbacks.registerContextMenuFactory(this);
        addMenuTab();
    }

	@Override
	public void processHttpMessage(int toolFlag,boolean messageIsRequest,IHttpRequestResponse messageInfo) throws UnsupportedEncodingException {
		if (toolFlag == (toolFlag & frame.checkEnabledFor())) {
			if (messageIsRequest) {
				String originRequest = new String(messageInfo.getRequest());
				StringBuilder output = new StringBuilder();
				IRequestInfo analyzedRequest = helpers.analyzeRequest(messageInfo);
				byte getSignParaType = getParameterType(analyzedRequest, frame.signPara);
				if (getHost(analyzedRequest).equals(frame.getHostFromUI()) && getSignParaType !=-1){
					output.append("Origin Request:\n");
					output.append(originRequest + "\n\n");
					callbacks.printOutput(output.toString());
					Map updatedParaMap = getUpdatedParaMapBaseOnTable(analyzedRequest);
					CCombinationConfig combinationConfig = new CCombinationConfig();
					String updatedParaStr = frame.combineString(updatedParaMap, combinationConfig);
					updatedParaStr=CHttpReqRespUtil.processEscapedString(updatedParaStr);

					String timeStamp = "";
					if (frame.timestampPara != null && frame.timestampPara.isEmpty()){
						timeStamp = updatedParaMap.get(frame.timestampPara).toString();
					}else {
						timeStamp = Long.toString(System.currentTimeMillis() / 1000);
						if (!frame.get10timestamp()) {
							timeStamp = Long.toString(System.currentTimeMillis());
						}
					}

					String newSign = frame.calculateNewSign(java.net.URLDecoder.decode(updatedParaStr,"UTF-8"));

					byte[] newRequest;
					if (getSignParaType == IHttpReqRespUtil.PARAM_HEADER) {// Sign in header, getSignParaType==10
						LinkedHashMap<String, String> rawHeadersMap = CHttpReqRespUtil.getHeadersMap(analyzedRequest.getHeaders());
						for (Map.Entry<String, String> rawHeaderEntry : rawHeadersMap.entrySet()) {
							String rawHeaderName = rawHeaderEntry.getKey();
							if (rawHeaderName.equals(frame.signPara)) {
								rawHeadersMap.put(rawHeaderName, newSign);
							}
						}
						// Process like ""GET / HTTP/1.1""
						String headerFirstLine = analyzedRequest.getHeaders().get(0);
						ArrayList<String> newHeaders = CHttpReqRespUtil.convertHeadersMapToList(rawHeadersMap);
						newHeaders.add(0,headerFirstLine);
						if (analyzedRequest.getContentType() == burp.IRequestInfo.CONTENT_TYPE_JSON) {
							String updatedJsonBody = JSON.toJSONString(updatedParaMap);
							updatedJsonBody = CHttpReqRespUtil.processEscapedString(CHttpReqRespUtil.processEscapedString(updatedJsonBody));
							byte[] newRequestBody = updatedJsonBody.getBytes("UTF-8");
							newRequest = helpers.buildHttpMessage(newHeaders, newRequestBody);
							} else {
							String newRequestBodyString = originRequest.substring(analyzedRequest.getBodyOffset());
							byte[] newRequestBody = newRequestBodyString.getBytes(StandardCharsets.ISO_8859_1);
							newRequest = helpers.buildHttpMessage(newHeaders, newRequestBody);
							}
						} else { // Sign in parameter,
							if (analyzedRequest.getContentType() == burp.IRequestInfo.CONTENT_TYPE_JSON) {
								updatedParaMap.put(frame.signPara, newSign);
								String updatedJsonBody = JSON.toJSONString(updatedParaMap);
								updatedJsonBody = CHttpReqRespUtil.processEscapedString(CHttpReqRespUtil.processEscapedString(updatedJsonBody));
								byte[] newRequestBody = updatedJsonBody.getBytes("UTF-8");
								List<String> newHeaders = analyzedRequest.getHeaders();
								newRequest = helpers.buildHttpMessage(newHeaders, newRequestBody);
								//messageInfo.setRequest(newRequest);
							} else {
								IParameter newSignPara = helpers.buildParameter(frame.signPara, newSign, getSignParaType);
								//IParameter newTimeStamp = helpers.buildParameter(frame.timestampPara, )
								newRequest = helpers.updateParameter(messageInfo.getRequest(), newSignPara);
								//messageInfo.setRequest(newRequest);
							}
						}

					//Sometimes timestamps are used multiple times
					String newRequestProcessTimeStamp = new String(newRequest, StandardCharsets.UTF_8);
					if (newRequestProcessTimeStamp.contains("<timestamp>")) {
						newRequestProcessTimeStamp = newRequestProcessTimeStamp.replace("<timestamp>", timeStamp);
					}
					newRequest = newRequestProcessTimeStamp.getBytes(StandardCharsets.ISO_8859_1);
					messageInfo.setRequest(newRequest);

					output.setLength(0); //reset the output
					output.append("==allParams====allParams==\n" + updatedParaStr + "\n");
					output.append("==Sign====Sign==\n" + newSign + "\n");
					output.append("Changed Request:\n");
					output.append(new String(messageInfo.getRequest()) + "\n\n");
					callbacks.printOutput(output.toString());
				}
			}
		}
	}




	private Map<String, String> getUpdatedParaMapBaseOnTable(IRequestInfo request) {
		//获取原始http的parameter与header的map
    	//当body是json格式的时候，这个方法也可以正常获取到键值对
		Map<String,String> rawParasMap = CHttpReqRespUtil.getParaMap(request.getParameters());
		Map<String, String> rawHeadersMap = CHttpReqRespUtil.getHeadersMap(request.getHeaders());

		//获取面板的参数Map
		Map<String,String> panelParaMap = frame.getParaFromTable();

		//对比面板中的参数和原始http的参数
		for (Map.Entry<String,String> rawParaEntry : rawParasMap.entrySet()){
			String rawParaName = rawParaEntry.getKey();
			String rawParaValue = rawParaEntry.getValue();

			//对比面板中的参数和原始http的参数是否一致
			if (panelParaMap.containsKey(rawParaName)) {
				String valueInParaMap = panelParaMap.get(rawParaName);

				if (valueInParaMap.contains("<timestamp>")) {
					String timestamp = Long.toString(System.currentTimeMillis() / 1000);
					if (!frame.get10timestamp()) {
						timestamp = Long.toString(System.currentTimeMillis());
					}
					rawParaValue = rawParaValue.replace("<timestamp>", timestamp);
				} else {
					//http传输必须符合ISO8859-1编码规范，b_iso88591的长度为1，而中文字符b_utf8的长度为3，不指定编码会出现转换错误。
					//timestamp一定是数字型，无需中文转换。其他的参数都需要进行一次utf-8转换防止中文乱码。
					String strChineseUTF8 = new String((rawParaValue.getBytes(StandardCharsets.ISO_8859_1)), StandardCharsets.UTF_8);
					rawParaValue = strChineseUTF8;
				}
				panelParaMap.put(rawParaName, rawParaValue);
			}//else 不一致的参数被舍弃
		}

		//对比面板中的参数和原始http的header
		for (Map.Entry<String, String> rawHeaderEntry : rawHeadersMap.entrySet()) {
			String rawHeaderName = rawHeaderEntry.getKey();
			String rawHeaderValue = rawHeaderEntry.getValue();
			//对比面板中的参数是否包含原始http的header
			if (panelParaMap.containsKey(rawHeaderName)) {
				String valueInParaMap = panelParaMap.get(rawHeaderName);
				if (valueInParaMap.contains("<timestamp>")) {
					String timestamp = Long.toString(System.currentTimeMillis() / 1000);
					if (!frame.get10timestamp()) {
						timestamp = Long.toString(System.currentTimeMillis());
					}
					rawHeaderName = rawHeaderName.replace("<timestamp>", timestamp);
				} else {
					//http传输必须符合ISO8859-1编码规范，b_iso88591的长度为1，而中文字符b_utf8的长度为3，不指定编码会出现转换错误。
					//timestamp一定是数字型，无需中文转换。其他的参数都需要进行一次utf-8转换防止中文乱码。
					String strChineseUTF8 = new String((rawHeaderName.getBytes(StandardCharsets.ISO_8859_1)), StandardCharsets.UTF_8);
					rawHeaderName = strChineseUTF8;
				}
				panelParaMap.put(rawHeaderName, rawHeaderValue);
			}//else 不一致的参数被舍弃
		}

		return panelParaMap;
	}


	public String getHost(IRequestInfo analyzeRequest) {
		List<String> headers = analyzeRequest.getHeaders();
		String domain = "";
		for (String header : headers) {
			if (header.toLowerCase().startsWith("host:")) { // 使用 startsWith() 方法判断是否包含 Host 字段
				domain = header.substring(5).trim(); // 将 Host 字段的值提取出来，并去除前后空格
				break; // 找到 Host 字段后即可退出循环
			}
		}
		return domain;
	}



	/**获取签名或者时间戳的类型，不存在sign参数时为-1，实际上用来判断参数是否存在**/
	private byte getParameterType(IRequestInfo request, String parameterName) {
		List<IParameter> parameters = request.getParameters();
		for (IParameter parameter : parameters) {
			if (parameter.getName().equals(parameterName)) {
				return parameter.getType();
			}
		}
		Map<String, String> rawHeadersMap = CHttpReqRespUtil.getHeadersMap(request.getHeaders());
		for (Map.Entry<String, String> rawHeaderEntry : rawHeadersMap.entrySet()) {
			String rawHeaderName = rawHeaderEntry.getKey();
			if (rawHeaderName.equals(parameterName)) {
				return IHttpReqRespUtil.PARAM_HEADER;
			}
		}
		return -1;
	}

	


	
	
	//以下是各种burp必须的方法 --start
    
    public void addMenuTab()
    {
      SwingUtilities.invokeLater(new Runnable()
      {
        public void run()
        {
			frame.CGUI();
          BurpExtender.this.callbacks.addSuiteTab(BurpExtender.this); //这里的BurpExtender.this实质是指ITab对象，也就是getUiComponent()中的contentPane.这个参数由CGUI()函数初始化。
          //如果这里报java.lang.NullPointerException: Component cannot be null 错误，需要排查contentPane的初始化是否正确。
        }
      });
    }
    
    
    
    //ITab必须实现的两个方法
	@Override
	public String getTabCaption() {
		// TODO Auto-generated method stub
		return ("ReSign");
	}
	@Override
	public Component getUiComponent() {
		// TODO Auto-generated method stub
		return frame.contentPane;
	}
	//ITab必须实现的两个方法
	
	
	
	//IContextMenuFactory 必须实现的方法
	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation)
	{ //需要在签名注册！！callbacks.registerContextMenuFactory(this);
	    IHttpRequestResponse[] messages = invocation.getSelectedMessages();
	    List<JMenuItem> list = new ArrayList<JMenuItem>();
	    if((messages != null) && (messages.length > 0))
	    {
	        //this.callbacks.printOutput("Messages in array: " + messages.length);
	        
	        //final IHttpService service = messages[0].getHttpService();
	    	final byte[] sentRequestBytes = messages[0].getRequest();
	    	IRequestInfo analyzeRequest = helpers.analyzeRequest(sentRequestBytes);
	    	
	        JMenuItem menuItem = new JMenuItem("Send to ReSign");
	        menuItem.addActionListener(new ActionListener()
	        {
	          public void actionPerformed(ActionEvent e)
	          {
	            try
	            {
	            	frame.textFieldDomain.setText(getHost(analyzeRequest));
	            	
	            	DefaultTableModel tableModel = (DefaultTableModel) frame.table.getModel();
	            	tableModel.setRowCount(0);//为了清空之前的数据
	            	
	            	Map<String,String> paraMap = CHttpReqRespUtil.getParaMap(analyzeRequest);
	            	//stdout.println(paraMap);
	            	//stdout.print(paraMap.keySet());
	            	for(String key:paraMap.keySet()){
	            		tableModel.addRow(new Object[]{URLDecoder.decode(key),URLDecoder.decode(paraMap.get(key))});
	            	}
	            }
	            catch (Exception e1)
	            {
	                BurpExtender.this.callbacks.printError(e1.getMessage());
	            }
	          }
	        });
	        list.add(menuItem);
	    }
	    return list;
	}
	//各种burp必须的方法 --end
	
}