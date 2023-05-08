package burp;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

import java.awt.BorderLayout;
import java.awt.Color;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

import java.awt.GridLayout;

import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.ActionEvent;


import java.awt.Component;
import java.awt.Cursor;
import java.awt.Desktop;
import java.io.PrintWriter;
import java.net.URI;
import java.net.URLDecoder;
import java.util.stream.Collectors;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONException;
import com.alibaba.fastjson.JSONObject;
import custom.CMD5;
import custom.CSHA1;
import org.apache.commons.lang3.*;

public class BurpExtender implements IBurpExtender, IHttpListener, ITab, IContextMenuFactory
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;//现在这里定义变量，再在registerExtenderCallbacks函数中实例化，如果都在函数中就只是局部变量，不能在这实例化，因为要用到其他参数。
	public JCheckBox chckbxProxy;
	public JCheckBox chckbxScanner;
	public JCheckBox chckbxIntruder;
	public JCheckBox chckbxRepeater;
	public static JTextField textFieldDomain;
	public static JTable table;
	public JTextField textFieldSecretKey;
	public JCheckBox chckbxAppendToEnd;
	public JCheckBox chckbxSameAsPara;
	public JTextField textFieldConnector;
	public JTextArea textAreaFinalString;
	public JCheckBox chckbxMD5;
	public JCheckBox chckbxSHA1;
	public JCheckBox chckbxNewCheckBox_3;
	public JTextArea textAreaSign;
	public JPanel contentPane;
	private final ButtonGroup buttonGroup = new ButtonGroup();
	private final ButtonGroup buttonGroup1 = new ButtonGroup();
	private final ButtonGroup buttonGroup2 = new ButtonGroup();
	public String extenderName = "Resign Plus v1.04 by R4ph4e1";
	private JTextField textFieldParaConnector;
	public JLabel lblOrderMethod;
	
	
	
	public String secretKey = null;
	public int sortedColumn;
	public SortOrder sortedMethod;
	public String howDealKey = ""; //sameAsPara  or appendToEnd
	String signPara = null; //the key name of sign parameter
	String timestampPara = null; //the key name of timestamp parameter
	private JTextField textFieldSign;
	private JTextField textFieldTimestamp;
	private JCheckBox chckbxOnlyUseValue;

	private JCheckBox chckbxOnlyUseKeyValue;
	private JTextField textFieldParaPrefixer;
	private JTextField textFieldParaSuffixer;
	private JCheckBox chckbx10timestamp;
	private JCheckBox chckbx13timestamp;
	private JCheckBox chckbxMD5u;


	// implement IBurpExtender
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {//当加载插件的时候，会调用下面的方法。
    	stdout = new PrintWriter(callbacks.getStdout(), true);
    	//PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true); 这种写法是定义变量和实例化，这里的变量就是新的变量而不是之前class中的全局变量了。
    	stdout.println(extenderName+"    Modified from Resign v2.2(Original author: bit4woo)\r\n");
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
		// 判断工具标志位是否匹配
		//不同的toolflag代表了不同的burp组件 https://portswigger.net/burp/extender/api/constant-values.html#burp.IBurpExtenderCallbacks
		if (toolFlag == (toolFlag & checkEnabledFor())) {
			// 请求包处理
			if (messageIsRequest) {
				// 获取原始请求
				String originRequest = new String(messageInfo.getRequest());
				// 输出原始请求
				callbacks.printOutput("Origin Request:\n");
				callbacks.printOutput(originRequest + "\n\n");
				// 解析请求
    			IRequestInfo analyzedRequest = helpers.analyzeRequest(messageInfo);
                byte getSignParaType = getParameterType(analyzedRequest, signPara);
				byte getTimestampParaType = getParameterType(analyzedRequest, timestampPara);
                //*******************recalculate sign**************************//
				// 判断是否满足更新条件,检查图形面板上的各种参数是否都存在
				if (getHost(analyzedRequest).equals(getHostFromUI()) && getSignParaType !=-1){
					// 更新参数
					Map updatedParaMap = getUpdatedParaMapBaseOnTable(analyzedRequest);
//					processEscapedJson(updatedParaMap);
					String updatedParaStr = combineString(updatedParaMap,getOnlyKeyValueConfig(),getOnlyValueConfig(),getParaConnector(),getParaPrefixer(),getParaSuffixer());
					updatedParaStr=processEscapedString(updatedParaStr);
					String newSign = calculateNewSign(java.net.URLDecoder.decode(updatedParaStr,"UTF-8"));

					if(analyzedRequest.getContentType()==burp.IRequestInfo.CONTENT_TYPE_JSON){
						//更新参数Sign
						updatedParaMap.put(signPara,newSign);
						String updatedJsonBody = JSON.toJSONString(updatedParaMap);
						updatedJsonBody=processEscapedString(processEscapedString(updatedJsonBody));
						byte[] newRequestBody = updatedJsonBody.getBytes("UTF-8");
						List<String> newHeaders = analyzedRequest.getHeaders();
						byte[] newRequest = helpers.buildHttpMessage(newHeaders, newRequestBody);
						messageInfo.setRequest(newRequest);
					} else {
						//非json时，helpers.updateParameter()可以重新组合参数并更新到请求包中
						//如果参数是PARAM_JSON类型，helpers.updateParameter()方法是不适用的
						//更新参数列表中的Sign
						IParameter newSignPara = helpers.buildParameter(signPara, newSign, getSignParaType);
						byte[] newRequest = helpers.updateParameter(messageInfo.getRequest(), newSignPara);
						//更新参数列表中TimeStamp
						if (timestampPara!=null){
							String newTimestamp = updatedParaMap.get(timestampPara).toString();
							IParameter newTimestampPara =
									helpers.buildParameter(timestampPara, newTimestamp, getTimestampParaType);
							newRequest = helpers.updateParameter(newRequest, newTimestampPara);
						}
						messageInfo.setRequest(newRequest);
					}
					callbacks.printOutput("Changed Request:\n");
					callbacks.printOutput(new String(messageInfo.getRequest()) + "\n\n");
				}
			}
		}  		
	}

	public static String processEscapedString (String str) {
		boolean hasEscapedChars = str.contains("\\\"");
//		String unescapedString = "";
		if (hasEscapedChars) {
			str= str.replace("\\\"", "\"");

		}
    	return str;
	}

    /**
     * Processes escaped JSON strings in a given Map.
     */
    public static void processEscapedJson(Map<String, Object> map) {
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            Object value = entry.getValue();
            if (value == null) {
                continue;
            } else if (value instanceof String) {
                String stringValue = (String) value;
                boolean hasEscapedChars = stringValue.contains("\\\"");
                if (hasEscapedChars && isJson(stringValue)) {
                    String unescapedString = JSON.parseObject(stringValue, String.class);
                    map.put(entry.getKey(), unescapedString);
                }
            } else if (value instanceof Map) {
                processEscapedJson((Map<String, Object>) value);
            }
        }
    }

    /**
     * Returns true if the given string is valid JSON.
     */
    private static boolean isJson(String str) {
        try {
            JSONObject.parseObject(str);
            return true;
        } catch (JSONException e) {
            return false;
        }
    }

	private Map<String, String> getUpdatedParaMapBaseOnTable(IRequestInfo request) {
		//当body是json格式的时候，这个方法也可以正常获取到键值对
    	List<IParameter> paras = request.getParameters();
		Map<String,String> paraMap = getParaFromTable();
		for (IParameter para:paras){
			String paraName = para.getName();
			String paraValue = para.getValue();

			if (paraMap.containsKey(paraName)) {
				String valueInParaMap = paraMap.get(paraName);

				if (valueInParaMap.contains("<timestamp>")) {
					String timestamp = Long.toString(System.currentTimeMillis() / 1000);
					if (!get10timestamp()) {
						timestamp = Long.toString(System.currentTimeMillis());
					}
					paraValue = paraValue.replace("<timestamp>", timestamp);
				} else {
					//http传输必须符合ISO8859-1编码规范，b_iso88591的长度为1，而中文字符b_utf8的长度为3，不指定编码会出现转换错误。
					//timestamp一定是数字型，无需中文转换。其他的参数都需要进行一次utf-8转换防止中文乱码。
					String strChineseUTF8 = new String((paraValue.getBytes(StandardCharsets.ISO_8859_1)), StandardCharsets.UTF_8);
					paraValue = strChineseUTF8;
				}
				paraMap.put(paraName, paraValue);
			}
		}
		return paraMap;
	}

	// Function to combine strings from a map
	public String combineString(Map<String, String> paraMap, boolean onlyKeyValue, boolean onlyValue, String paraConnector, String paraPrefixer, String paraSuffixer) {
		// Get the secret key configuration
		getSecKeyConfig();
		// Create a string builder
		StringBuilder sb = new StringBuilder();
		// If the key is the same as the parameter
		if ("sameAsPara".equals(howDealKey)){
			// Get the text from the secret key
			secretKey = textFieldSecretKey.getText();
			// If the secret key contains an equal sign and has two parts
			if(secretKey.contains("=") & secretKey.split("=").length==2){
				// Put the key and value into the map
				paraMap.put(secretKey.split("=")[0], secretKey.split("=")[1]);
			}
		}
		// If the order method is custom
		if ("Custom Order".equals(lblOrderMethod.getText())) {
			// Set a boolean to track if it is the first entry
			boolean isFirst = true;
			// Loop through each entry in the map
			for (Map.Entry<String, String> para : paraMap.entrySet()) {
				// If it is not the first entry
				if (!isFirst) {
					// Append the connector
					sb.append(paraConnector);
				}
				// Set the boolean to false
				isFirst = false;
				// If only the value should be used
				if (onlyValue) {
					// Append the value
					sb.append(para.getValue());
				// If only the key and value should be used
				} else if (onlyKeyValue) {
					// Append the key and value
					sb.append(para.getKey()).append(para.getValue());
				// Otherwise
				} else {
					// Append the entry
					sb.append(para);
				}
			}
			// If there is a prefixer
			if (paraPrefixer != null && !paraPrefixer.isEmpty()) {
				// Insert the prefixer at the beginning
				sb.insert(0, paraPrefixer);
			}
			// If there is a suffixer
			if (paraSuffixer != null && !paraSuffixer.isEmpty()) {
				// Append the suffixer
				sb.append(paraSuffixer);
			}
		// Otherwise
		} else {
			// Create a sorted map
			Map<String, String> sortedMap;
			// If the sorted column is 0
			if(sortedColumn == 0) {
				// Sort the map by key
				sortedMap = custom.CMapSort.sortMapByKey(paraMap, sortedMethod.toString());
			// Otherwise
			} else {
				// Sort the map by value
				sortedMap = custom.CMapSort.sortMapByValue(paraMap, sortedMethod.toString());
			}
			// Append the combined map entry
			sb.append(custom.CMapSort.combineMapEntry(sortedMap, onlyKeyValue, onlyValue, paraConnector, paraPrefixer, paraSuffixer));
		}
		// If the key should be appended to the end
		if ("appendToEnd".equals(howDealKey)) {
			// Get the text from the secret key
			secretKey = textFieldSecretKey.getText();
			// Append the secret key
			sb.append(secretKey);
		}
		// Return the string
		return sb.toString();
	}
	

	//两个核心方法：1是拼接字符串，2是计算出sign
	public String calculateNewSign(String str){
		String sign = "Sign Error";
		if ("MD5l".equals(getSignAlgorithm())) { // 需要输出小写字母的 MD5
			sign = CMD5.GetMD5Code(str).toLowerCase(); // 将字符串转为小写后计算 MD5
		} else if ("MD5u".equals(getSignAlgorithm())) { // 需要输出大写字母的 MD5
			sign = CMD5.GetMD5Code(str).toUpperCase(); // 将字符串转为大写后计算 MD5
		} else if ("SHA1".equals(getSignAlgorithm())) {
			sign = CSHA1.SHA1(str);
		}
		return sign;
	}

	public Map<String, String> getParaFromTable() {
		Map<String, String> tableParas = new LinkedHashMap<>();
		for (int i = 0; i < table.getRowCount(); i++) {
			String key = table.getValueAt(i, 0).toString();
			String value = table.getValueAt(i, 1).toString();

			if (!key.equals(getSignPara())) {
				tableParas.put(key, value);
			}
		}
		return tableParas;
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


	public void CGUI() {
		
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		contentPane.setLayout(new BorderLayout(0, 0));

		
		JPanel enableConfigPanel = new JPanel();
		enableConfigPanel.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		FlowLayout flowLayout = (FlowLayout) enableConfigPanel.getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);
		contentPane.add(enableConfigPanel, BorderLayout.NORTH);
		
		
		JPanel panel_3 = new JPanel();
		panel_3.setBorder(null);
		enableConfigPanel.add(panel_3);
		panel_3.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));
		
		JLabel enableFor = new JLabel("Enable For :");
		panel_3.add(enableFor);
		
		chckbxProxy = new JCheckBox("Proxy");
		panel_3.add(chckbxProxy);
		
		chckbxScanner = new JCheckBox("Scanner");
		panel_3.add(chckbxScanner);
		
		chckbxIntruder = new JCheckBox("Intruder");
		panel_3.add(chckbxIntruder);
		
		chckbxRepeater = new JCheckBox("Repeater");
		chckbxRepeater.setSelected(true);
		panel_3.add(chckbxRepeater);
		
		JPanel panel_1 = new JPanel();
		panel_1.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		contentPane.add(panel_1, BorderLayout.SOUTH);
		panel_1.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
		
		JLabel lblNewLabel = new JLabel(extenderName+"  |  Modified from Resign v2.2(click to view the original project)");
		lblNewLabel.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				try {
					URI uri = new URI("https://github.com/PolarisLab/GUI_Burp_Extender_ReSign");
					Desktop desktop = Desktop.getDesktop();
					if(Desktop.isDesktopSupported()&&desktop.isSupported(Desktop.Action.BROWSE)){
						desktop.browse(uri);
					}
				} catch (Exception e2) {
					// TODO: handle exception
					BurpExtender.this.callbacks.printError(e2.getMessage());
				}
				
			}
			@Override
			public void mouseEntered(MouseEvent e) {
				lblNewLabel.setForeground(Color.BLUE);
			}
			@Override
			public void mouseExited(MouseEvent e) {
				lblNewLabel.setForeground(Color.BLACK);
			}
		});
		lblNewLabel.setHorizontalAlignment(SwingConstants.LEFT);
		panel_1.add(lblNewLabel);
		
		JPanel panel = new JPanel();
		panel.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		contentPane.add(panel, BorderLayout.CENTER);
		panel.setLayout(new BorderLayout(0, 0));
		
		JPanel panel_5 = new JPanel();
		panel.add(panel_5, BorderLayout.NORTH);
		panel_5.setLayout(new GridLayout(0, 1, 0, 0));
		
		JLabel lblURL = new JLabel("Domain:");
		panel_5.add(lblURL);
		
		textFieldDomain = new JTextField();
		panel_5.add(textFieldDomain);
		textFieldDomain.setColumns(20);
		
		JLabel lblParas = new JLabel("[1] Parameters:(Click Table Header To Sort Or Move Up And Down To Custom)");
		panel_5.add(lblParas);
		
		JScrollPane panel_6 = new JScrollPane();
		panel_6.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		panel.add(panel_6, BorderLayout.CENTER);
		
		table = new JTable();
		table.getTableHeader().addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				try {
					sortedColumn = table.getRowSorter().getSortKeys().get(0).getColumn();
					//System.out.println(sortedColumn);
					sortedMethod = table.getRowSorter().getSortKeys().get(0).getSortOrder();
					System.out.println(sortedMethod); //ASCENDING   DESCENDING
				} catch (Exception e1) {
					sortedColumn = -1;
					sortedMethod = null;
					BurpExtender.this.callbacks.printError(e1.getMessage());
				}
//				System.out.println(sortedColumn);
//				System.out.println(sortedMethod);
				lblOrderMethod.setText(table.getColumnName(sortedColumn)+" "+sortedMethod);
			}
		});
		table.setColumnSelectionAllowed(true);
		table.setCellSelectionEnabled(true);
		table.setSurrendersFocusOnKeystroke(true);
		table.setFillsViewportHeight(true);
		table.setCursor(Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR));
		DefaultTableModel tableModel = new DefaultTableModel(
				new Object[][] {
					//{null, null},
				},
				new String[] {
					"Key", "Value"
				});
		RowSorter<TableModel> sorter = new TableRowSorter<TableModel>(tableModel);
		table.setRowSorter(sorter);
		panel_6.setViewportView(table);
		table.setModel(tableModel);
		
		JPanel panel_7 = new JPanel();
		panel.add(panel_7, BorderLayout.EAST);
		GridBagLayout gbl_panel_7 = new GridBagLayout();
		gbl_panel_7.columnWidths = new int[]{93, 0};
		gbl_panel_7.rowHeights = new int[]{23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		gbl_panel_7.columnWeights = new double[]{1.0, Double.MIN_VALUE};
		gbl_panel_7.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		panel_7.setLayout(gbl_panel_7);



		JButton btnMarkAsSign = new JButton("Mark As Sign Para");
		btnMarkAsSign.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (table.getSelectedRow() != -1){
					signPara = table.getValueAt(table.getSelectedRow(), 0).toString();
					textFieldSign.setText(signPara);
				}
			}
		});

		
		JButton btnMoveDown = new JButton("Move Down");
		btnMoveDown.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int selectedRow = table.getSelectedRow();
				int rowCount = table.getRowCount();
				if (selectedRow >= 0 && selectedRow < rowCount - 1) {
					Object[] selectedRowData = new Object[table.getColumnCount()];
					Object[] nextRowData = new Object[table.getColumnCount()];
					for (int i = 0; i < table.getColumnCount(); i++) {
						selectedRowData[i] = table.getValueAt(selectedRow, i);
						nextRowData[i] = table.getValueAt(selectedRow + 1, i);
					}
					((DefaultTableModel) table.getModel()).removeRow(selectedRow);
					((DefaultTableModel) table.getModel()).insertRow(selectedRow, nextRowData);
					((DefaultTableModel) table.getModel()).removeRow(selectedRow + 1);
					((DefaultTableModel) table.getModel()).insertRow(selectedRow + 1, selectedRowData);
					table.setRowSelectionInterval(selectedRow + 1, selectedRow + 1);
					lblOrderMethod.setText("Custom Order");
				} else if (selectedRow == rowCount - 1) {
					JOptionPane.showMessageDialog(null, "最后一行不能再向下移动！");
				}
			}
		});
		// btnMoveDown.addActionListener(new ActionListener() {
		// 	public void actionPerformed(ActionEvent e) {
		// 		// if (table.getSelectedRow() != -1 && table.getSelectedRow()+1 <= table.getRowCount()-1){
		// 		if (table.getSelectedRow() + 1 < table.getRowCount()) {
		// 			try{
		// 				int row = table.getSelectedRow();
		// 				String xkey = table.getValueAt(row, 0).toString();
		// 				String xvalue = table.getValueAt(row, 1).toString();
						
		// 				String tmpkey = table.getValueAt(row+1, 0).toString();
		// 				String tmpvalue = table.getValueAt(row+1, 1).toString();
						
		// 				//do exchange 
		// 				tableModel.setValueAt(tmpkey, row, 0);
		// 				tableModel.setValueAt(tmpvalue, row, 1);
						
		// 				tableModel.setValueAt(xkey, row+1, 0);
		// 				tableModel.setValueAt(xvalue, row+1, 1);
						
		// 				table.setRowSelectionInterval(row+1, row+1);//set the line selected

		// 				lblOrderMethod.setText("Custom Order");
		// 			} catch (IndexOutOfBoundsException e1) {
		// 				BurpExtender.this.callbacks.printError(e1.getMessage());
		// 			}
		// 		}
		// 	}
		// });
		
		// JButton btnMoveUp = new JButton("Move Up");
		// btnMoveUp.addActionListener(new ActionListener() {
		// 	public void actionPerformed(ActionEvent e) {
		// 		if (table.getSelectedRow() != -1 && table.getSelectedRow()-1 >=0){
		// 			try {
		// 				int row = table.getSelectedRow();
		// 				String xkey = table.getValueAt(row, 0).toString();
		// 				String xvalue = table.getValueAt(row, 1).toString();
						
		// 				String tmpkey = table.getValueAt(row-1, 0).toString();
		// 				String tmpvalue = table.getValueAt(row-1, 1).toString();
						
		// 				//do exchange 
		// 				tableModel.setValueAt(tmpkey, row, 0);
		// 				tableModel.setValueAt(tmpvalue, row, 1);
						
		// 				tableModel.setValueAt(xkey, row-1, 0);
		// 				tableModel.setValueAt(xvalue, row-1, 1);
						
		// 				table.setRowSelectionInterval(row-1, row-1);
						
		// 				lblOrderMethod.setText("Custom Order");
		// 			} catch (Exception e2) {
		// 				// TODO: handle exception
		// 				BurpExtender.this.callbacks.printError(e2.getMessage());
		// 			}

		// 		}
		// 	}
		// });

		JButton btnMoveUp = new JButton("Move Up");
		btnMoveUp.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int selectedRow = table.getSelectedRow();
				if (selectedRow > 0) {
					DefaultTableModel model = (DefaultTableModel) table.getModel();
					model.moveRow(selectedRow, selectedRow, selectedRow - 1); // Move row up
					table.setRowSelectionInterval(selectedRow - 1, selectedRow - 1); // Select moved row
					lblOrderMethod.setText("Custom Order");
				} else if (selectedRow == 0) {
					JOptionPane.showMessageDialog(null, "已经到达第一行，不能再向上移动！");
				}
			}
		});
		
		// JButton btnAdd = new JButton("Add");
		// btnAdd.addActionListener(new ActionListener() {
		// 	public void actionPerformed(ActionEvent e) {
		// 		DefaultTableModel model = (DefaultTableModel) table.getModel();
		// 		model.addRow(new Object[]{"key","value"});
		// 		lblOrderMethod.setText("Custom Order");
		// 	}
		// });
		
		// JButton btnNewButton = new JButton("Remove");
		// btnNewButton.addActionListener(new ActionListener() {
		// 	public void actionPerformed(ActionEvent e) {
		// 		int[] rowindexs = table.getSelectedRows();
		// 		for (int i=0; i < rowindexs.length; i++){
		// 			rowindexs[i] = table.convertRowIndexToModel(rowindexs[i]);//转换为Model的索引，否则排序后索引不对应。
		// 		}
		// 		Arrays.sort(rowindexs);
				
		// 		DefaultTableModel tableModel = (DefaultTableModel) table.getModel();
		// 		for(int i=rowindexs.length-1;i>=0;i--){
		// 			tableModel.removeRow(rowindexs[i]);
		// 		}
		// 		lblOrderMethod.setText("Custom Order");
		// 	}
		// });
		JButton btnAdd = new JButton("Add");
		btnAdd.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int selectedRow = table.getSelectedRow();
				if (selectedRow == -1) {
					JOptionPane.showMessageDialog(null, "请先选中一个单元格！");
				} else {
					Object[] rowData = new Object[table.getColumnCount()];
					for (int i = 0; i < table.getColumnCount(); i++) {
						rowData[i] = "";
					}
					int rowCount = table.getRowCount();
					if (selectedRow < rowCount - 1) {
						((DefaultTableModel) table.getModel()).insertRow(selectedRow + 1, rowData);
						table.setRowSelectionInterval(selectedRow + 1, selectedRow + 1);
					} else {
						((DefaultTableModel) table.getModel()).addRow(rowData);
						table.setRowSelectionInterval(rowCount, rowCount);
					}
					lblOrderMethod.setText("Custom Order");
				}
			}
		});;
		JButton btnNewButton = new JButton("Remove");
		btnNewButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int[] selectedRows = table.getSelectedRows(); // 获取被选中的行的索引
				if (selectedRows.length == 0) { // 如果没有选中行，弹出提示框，直接返回
					JOptionPane.showMessageDialog(null, "Please select at least one row to delete.");
					return;
				}
				DefaultTableModel tableModel = (DefaultTableModel) table.getModel(); // 获取表格模型
				for(int i=selectedRows.length-1; i>=0; i--){ // 从最后一行开始往上删除
					int row = table.convertRowIndexToModel(selectedRows[i]); 
					tableModel.removeRow(row);
				}
				lblOrderMethod.setText("Custom Order"); // 更新状态
			}
		});
		
		lblOrderMethod = new JLabel("Custom Order");
		GridBagConstraints gbc_lblOrderMethod = new GridBagConstraints();
		gbc_lblOrderMethod.insets = new Insets(0, 0, 5, 0);
		gbc_lblOrderMethod.gridx = 0;
		gbc_lblOrderMethod.gridy = 0;
		panel_7.add(lblOrderMethod, gbc_lblOrderMethod);
		GridBagConstraints gbc_btnNewButton = new GridBagConstraints();
		gbc_btnNewButton.insets = new Insets(0, 0, 5, 0);
		gbc_btnNewButton.gridx = 0;
		gbc_btnNewButton.gridy = 1;
		panel_7.add(btnNewButton, gbc_btnNewButton);
		GridBagConstraints gbc_btnAdd = new GridBagConstraints();
		gbc_btnAdd.insets = new Insets(0, 0, 5, 0);
		gbc_btnAdd.gridx = 0;
		gbc_btnAdd.gridy = 2;
		panel_7.add(btnAdd, gbc_btnAdd);
		GridBagConstraints gbc_btnMoveUp = new GridBagConstraints();
		gbc_btnMoveUp.insets = new Insets(0, 0, 5, 0);
		gbc_btnMoveUp.gridx = 0;
		gbc_btnMoveUp.gridy = 3;
		panel_7.add(btnMoveUp, gbc_btnMoveUp);
		GridBagConstraints gbc_btnMoveDown = new GridBagConstraints();
		gbc_btnMoveDown.insets = new Insets(0, 0, 5, 0);
		gbc_btnMoveDown.gridx = 0;
		gbc_btnMoveDown.gridy = 4;
		panel_7.add(btnMoveDown, gbc_btnMoveDown);
		GridBagConstraints gbc_btnMarkAsSign = new GridBagConstraints();
		gbc_btnMarkAsSign.insets = new Insets(0, 0, 5, 0);
		gbc_btnMarkAsSign.gridx = 0;
		gbc_btnMarkAsSign.gridy = 6;
		panel_7.add(btnMarkAsSign, gbc_btnMarkAsSign);

		textFieldSign = new JTextField();
		GridBagConstraints gbc_textFieldSign = new GridBagConstraints();
		gbc_textFieldSign.insets = new Insets(0, 0, 5, 0);
		gbc_textFieldSign.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldSign.gridx = 0;
		gbc_textFieldSign.gridy = 7;
		panel_7.add(textFieldSign, gbc_textFieldSign);
		textFieldSign.setColumns(10);




		JButton btnMarkAsTimestamp = new JButton("Mark As Timestamp Para");
		btnMarkAsTimestamp.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (table.getSelectedRow() != -1){
					timestampPara = table.getValueAt(table.getSelectedRow(), 0).toString();
					table.setValueAt("<timestamp>",table.getSelectedRow(), 1);
					textFieldTimestamp.setText(timestampPara);
				}
			}
		});

		GridBagConstraints gbc_btnMarkAsTimestamp = new GridBagConstraints();
		gbc_btnMarkAsTimestamp.insets = new Insets(0, 0, 5, 0);
		gbc_btnMarkAsTimestamp.gridx = 0;
		gbc_btnMarkAsTimestamp.gridy = 8;
		panel_7.add(btnMarkAsTimestamp, gbc_btnMarkAsTimestamp);

		textFieldTimestamp = new JTextField();
		GridBagConstraints gbc_textFieldTimestamp = new GridBagConstraints();
		gbc_textFieldTimestamp.insets = new Insets(0, 0, 5, 0);
		gbc_textFieldTimestamp.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldTimestamp.gridx = 0;
		gbc_textFieldTimestamp.gridy = 9;
		panel_7.add(textFieldTimestamp, gbc_textFieldTimestamp);
		textFieldTimestamp.setColumns(10);



		JButton button = new JButton("Show Final String");
		button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				//System.out.println(getOnlyValueConfig());
				//System.out.println(getSignPara());
				if (getSignPara().equals("")){
					textAreaFinalString.setText("error! sign parameter must be specified!");
				}else{
					String str = combineString(getParaFromTable(),getOnlyKeyValueConfig(),getOnlyValueConfig(),getParaConnector(),getParaPrefixer(),getParaSuffixer());
					if (str.contains("<timestamp>")){
						if(get13timestamp()){
							str = str.replace("<timestamp>", Long.toString(System.currentTimeMillis()));//需要重新赋值，否则不会被更新
						}else if(get10timestamp()){
							str = str.replace("<timestamp>", Long.toString(System.currentTimeMillis()/1000));//需要重新赋值，否则不会被更新
						}
					}
					textAreaFinalString.setText(str);
				}
			}
		});
		GridBagConstraints gbc_button = new GridBagConstraints();
		gbc_button.insets = new Insets(0, 0, 5, 0);
		gbc_button.gridx = 0;
		gbc_button.gridy = 10;
		panel_7.add(button, gbc_button);
		
		
		
		JPanel panel_8 = new JPanel();
		panel_8.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		panel.add(panel_8, BorderLayout.SOUTH);
		panel_8.setLayout(new GridLayout(0, 1, 0, 0));
		
		JLabel lblSecretKey = new JLabel("[2] Secret Key :");
		panel_8.add(lblSecretKey);
		
		textFieldSecretKey = new JTextField();
		panel_8.add(textFieldSecretKey);
		textFieldSecretKey.setHorizontalAlignment(SwingConstants.LEFT);
		textFieldSecretKey.setColumns(50);
		
		
		chckbxSameAsPara = new JCheckBox("Add secret key as a parameter. eg. key=secretkey");
		panel_8.add(chckbxSameAsPara);
		chckbxSameAsPara.setSelected(true);
		buttonGroup.add(chckbxSameAsPara);
		
		chckbxAppendToEnd = new JCheckBox("Append to the end of sorted Parameters. eg. &key=secretkey");
		panel_8.add(chckbxAppendToEnd);
		buttonGroup.add(chckbxAppendToEnd);
		
		JLabel lblNewLabel_1 = new JLabel("[3] How To Combine\uFF1A ");
		panel_8.add(lblNewLabel_1);
		
		chckbxOnlyUseValue = new JCheckBox("Only Use Value");
		panel_8.add(chckbxOnlyUseValue);

		chckbxOnlyUseKeyValue = new JCheckBox("Only Use KeyValue");
		panel_8.add(chckbxOnlyUseKeyValue);

		chckbx10timestamp = new JCheckBox("10-digtal-timestamp");
		panel_8.add(chckbx10timestamp);
		buttonGroup2.add(chckbx10timestamp);

		chckbx13timestamp = new JCheckBox("13-digtal-timestamp");
		chckbx13timestamp.setSelected(true);
		panel_8.add(chckbx13timestamp);
		buttonGroup2.add(chckbx13timestamp);


		JLabel lblConnecStringPrefix = new JLabel("add Prefix");
		panel_8.add(lblConnecStringPrefix);

		textFieldParaPrefixer = new JTextField();
		panel_8.add(textFieldParaPrefixer);
		textFieldParaPrefixer.setColumns(50);

		JLabel lblConnecStringSuffix = new JLabel("add Suffix");
		panel_8.add(lblConnecStringSuffix);

		textFieldParaSuffixer = new JTextField();
		panel_8.add(textFieldParaSuffixer);
		textFieldParaSuffixer.setColumns(50);

		JLabel lblConnecStringBetween = new JLabel("connection string between each parameter");
		panel_8.add(lblConnecStringBetween);

		
		textFieldParaConnector = new JTextField();
		textFieldParaConnector.setText("&");
		panel_8.add(textFieldParaConnector);
		textFieldParaConnector.setColumns(50);
		
		
		JPanel panel_2 = new JPanel();
		panel_2.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		contentPane.add(panel_2, BorderLayout.EAST);
		panel_2.setLayout(new BorderLayout(0, 0));
		
		textAreaFinalString = new JTextArea();
		textAreaFinalString.setLineWrap(true);
		textAreaFinalString.setColumns(20);
		textAreaFinalString.setRows(20);
		panel_2.add(textAreaFinalString, BorderLayout.WEST);
		
		textAreaSign = new JTextArea();
		textAreaSign.setLineWrap(true);
		textAreaSign.setColumns(20);
		panel_2.add(textAreaSign, BorderLayout.EAST);
		
		JPanel panel_10 = new JPanel();
		panel_2.add(panel_10, BorderLayout.NORTH);
		GridBagLayout gbl_panel_10 = new GridBagLayout();
		gbl_panel_10.columnWidths = new int[]{108, 43, 109, 0};
		gbl_panel_10.rowHeights = new int[]{23, 0, 0, 0, 0};
		gbl_panel_10.columnWeights = new double[]{0.0, 0.0, 0.0, Double.MIN_VALUE};
		gbl_panel_10.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		panel_10.setLayout(gbl_panel_10);
		
		JLabel lblNewLabel_2 = new JLabel("Chose Sign Method:");
		GridBagConstraints gbc_lblNewLabel_2 = new GridBagConstraints();
		gbc_lblNewLabel_2.anchor = GridBagConstraints.WEST;
		gbc_lblNewLabel_2.insets = new Insets(0, 0, 5, 5);
		gbc_lblNewLabel_2.gridx = 0;
		gbc_lblNewLabel_2.gridy = 0;
		panel_10.add(lblNewLabel_2, gbc_lblNewLabel_2);
		
		chckbxMD5 = new JCheckBox("MD5[lower]");
		chckbxMD5.setSelected(true);
		GridBagConstraints gbc_chckbxMD5 = new GridBagConstraints();
		gbc_chckbxMD5.anchor = GridBagConstraints.NORTHWEST;
		gbc_chckbxMD5.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxMD5.gridx = 0;
		gbc_chckbxMD5.gridy = 1;
		panel_10.add(chckbxMD5, gbc_chckbxMD5);
		buttonGroup1.add(chckbxMD5);

		chckbxMD5u = new JCheckBox("MD5[upper]");
		chckbxMD5u.setSelected(false);
		GridBagConstraints gbc_chckbxMD5u = new GridBagConstraints();
		gbc_chckbxMD5u.anchor = GridBagConstraints.NORTHWEST;
		gbc_chckbxMD5u.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxMD5u.gridx = 0;
		gbc_chckbxMD5u.gridy = 2;
		panel_10.add(chckbxMD5u, gbc_chckbxMD5u);
		buttonGroup1.add(chckbxMD5u);
		
		chckbxSHA1 = new JCheckBox("SHA1");
		chckbxSHA1.setSelected(true);
		GridBagConstraints gbc_chckbxSHA1 = new GridBagConstraints();
		gbc_chckbxSHA1.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxSHA1.gridx = 1;
		gbc_chckbxSHA1.gridy = 1;
		panel_10.add(chckbxSHA1, gbc_chckbxSHA1);
		buttonGroup1.add(chckbxSHA1);
		
		chckbxNewCheckBox_3 = new JCheckBox("To be Continue");
		chckbxNewCheckBox_3.setSelected(true);
		chckbxNewCheckBox_3.setEnabled(false);
		GridBagConstraints gbc_chckbxNewCheckBox_3 = new GridBagConstraints();
		gbc_chckbxNewCheckBox_3.insets = new Insets(0, 0, 5, 0);
		gbc_chckbxNewCheckBox_3.anchor = GridBagConstraints.NORTHWEST;
		gbc_chckbxNewCheckBox_3.gridx = 2;
		gbc_chckbxNewCheckBox_3.gridy = 1;
		panel_10.add(chckbxNewCheckBox_3, gbc_chckbxNewCheckBox_3);
		
		JPanel panel_11 = new JPanel();
		panel_2.add(panel_11, BorderLayout.CENTER);
		
		JButton btnSign = new JButton("Sign");
		btnSign.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				textAreaSign.setText(calculateNewSign(textAreaFinalString.getText()));
			}
		});
		panel_11.add(btnSign);
	}
	
	
    
    
    //各种从图形面板或者从数据包获取参数，获取配置的函数。--start
    
	public int checkEnabledFor(){
		//get values that should enable this extender for which Component.
		int status = 0;
		if (chckbxIntruder.isSelected()){
			status += 32;
		}
		if(chckbxProxy.isSelected()){
			status += 4;
		}
		if(chckbxRepeater.isSelected()){
			status += 64;
		}
		if(chckbxScanner.isSelected()){
			status += 16;
		}
		return status;
	}
	
	
	public void getSecKeyConfig() {
		if (secretKey != null && secretKey != ""){
			secretKey = textFieldSecretKey.getText();
		}
		if(chckbxAppendToEnd.isSelected()){
			howDealKey = "appendToEnd";
		}
		else if (chckbxSameAsPara.isSelected()) {
			howDealKey = "sameAsPara";
		}
	}

	public boolean getOnlyKeyValueConfig() {
		if(chckbxOnlyUseKeyValue.isSelected()){
			return true;
		}else{
			return false;
		}
	}

	public boolean getOnlyValueConfig() {
		if(chckbxOnlyUseValue.isSelected()){
			return true;
		}else{
			return false;
		}
	}

	public boolean get10timestamp() {
		if(chckbx10timestamp.isSelected()){
			return true;
		}else{
			return false;
		}
	}

	public boolean get13timestamp() {
		if(chckbx13timestamp.isSelected()){
			return true;
		}else{
			return false;
		}
	}

	public String getParaPrefixer() {
		return textFieldParaPrefixer.getText();
	}
	public String getParaSuffixer() {
		return textFieldParaSuffixer.getText();
	}

	public String getParaConnector() {
		return textFieldParaConnector.getText();
	}
	
	public String getSignPara(){
		return textFieldSign.getText();
	}
	
	public String getSignAlgorithm() {
		if (chckbxMD5.isSelected()){
			return "MD5l";
		}else if (chckbxMD5u.isSelected()){
			return "MD5u";
		}else if (chckbxSHA1.isSelected()) {
			return "SHA1";
		}else {
			return "null";
		}
	}
	

	/**以map形式获取参数顺序和列表**/
	public Map<String, String> getPara(IRequestInfo analyzeRequest){
    	List<IParameter> paras = analyzeRequest.getParameters();//当body是json格式的时候，这个方法也可以正常获取到键值对，牛掰。但是PARAM_JSON等格式不能通过updateParameter方法来更新。
    	Map<String,String> paraMap = new HashMap<String,String>();
    	for (IParameter para:paras){
			//http传输必须符合ISO8859-1编码规范，b_iso88591的长度为1，而中文字符b_utf8的长度为3，不指定编码会出现转换错误
			String strChineseUTF8 = new String((para.getValue().getBytes(StandardCharsets.ISO_8859_1)), StandardCharsets.UTF_8);
    		paraMap.put(para.getName(), strChineseUTF8);
    	}
    	return paraMap ;
	}

	/**以map形式获取参数顺序和列表**/
	public Map<String, String> getPara2(IRequestInfo analyzeRequest){
		List<IParameter> paras = analyzeRequest.getParameters();
		return paras.stream()
				.collect(Collectors.toMap(IParameter::getName, para -> {
					try {
						return URLEncoder.encode(para.getValue(), "UTF-8");
					} catch (UnsupportedEncodingException e) {
						throw new RuntimeException(e);
					}
				}));
	}

	/**获取签名或者时间戳的类型，不存在sign参数时为-1，实际上用来判断参数是否存在**/
	private byte getParameterType(IRequestInfo request, String parameterName) {
		List<IParameter> parameters = request.getParameters();
		for (IParameter parameter : parameters) {
			if (parameter.getName().equals(parameterName)) {
				return parameter.getType();
			}
		}
		return -1;
	}

	
	public String getHostFromUI(){
    	String domain = "";
    	domain = textFieldDomain.getText();
    	return domain ;
	}
	//各种从图形面板或者从数据包获取参数，获取配置的函数。--end

	
	
	//以下是各种burp必须的方法 --start
    
    public void addMenuTab()
    {
      SwingUtilities.invokeLater(new Runnable()
      {
        public void run()
        {
          BurpExtender.this.CGUI();
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
		return this.contentPane;
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
	            	textFieldDomain.setText(getHost(analyzeRequest));
	            	
	            	DefaultTableModel tableModel = (DefaultTableModel) table.getModel();
	            	tableModel.setRowCount(0);//为了清空之前的数据
	            	
	            	Map<String,String> paraMap = getPara(analyzeRequest);
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