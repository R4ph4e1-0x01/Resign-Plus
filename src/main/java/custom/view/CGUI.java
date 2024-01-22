package custom.view;

import burp.BurpExtender;
import custom.Algorithm.CMD5;
import custom.Algorithm.CSHA1;
import custom.Algorithm.CSHA256;
import custom.util.CCombinationConfig;
import custom.util.CMapSort;
import custom.util.ICombinationConfig;

import java.awt.BorderLayout;
import java.awt.EventQueue;

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
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;
import java.awt.event.ActionEvent;
import java.awt.Cursor;
import java.awt.Desktop;

import java.awt.Color;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import static javax.swing.SortOrder.UNSORTED;

public class CGUI extends JFrame {

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
	public JCheckBox chckbxSHA256;
	public JCheckBox chckbxNewCheckBox_3;
	public JTextArea textAreaSign;
	public JPanel contentPane;

	private final ButtonGroup buttonGroupKeyConfiguration = new ButtonGroup();
	private final ButtonGroup buttonGroupSignAlgorithm = new ButtonGroup();
	private final ButtonGroup buttonGroupTimestamp = new ButtonGroup();
	private final ButtonGroup buttonGroupCombinationType = new ButtonGroup();

	private JTextField textFieldParaConnector;
	public JLabel lblOrderMethod;

	private JTextField textFieldSign;
	private JTextField textFieldTimestamp;

	private JCheckBox chckbxOnlyUseValue;
	private JCheckBox chckbxOnlyUseKeyValue;
	private JCheckBox chckbxKeySymbolValue;

	private JTextField textFieldParaPrefixer;
	private JTextField textFieldParaSuffixer;
	private JCheckBox chckbx10timestamp;
	private JCheckBox chckbx13timestamp;
	private JCheckBox chckbxMD5u;

	public String extenderName = "Resign Plus v2.02 by R4ph4e1";
//	public String secretKey = null;
//	public int sortedColumn;
//	public SortOrder sortedMethod;
	//public String howDealKey = ""; //sameAsPara  or appendToEnd
	public String signPara = null; //the key name of sign parameter
	public String timestampPara = null; //the key name of timestamp parameter


	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					CGUI frame = new CGUI();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	public void CGUI() {

		CCombinationConfig combinationConfig = new CCombinationConfig();
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

		JLabel lblNewLabel = new JLabel(extenderName+"  |  Modified from Resign v2.2(Original author: bit4woo)");
		lblNewLabel.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				try {
					URI uri = new URI("https://github.com/R4ph4e1-0x01/Resign-Plus");
					Desktop desktop = Desktop.getDesktop();
					if(Desktop.isDesktopSupported()&&desktop.isSupported(Desktop.Action.BROWSE)){
						desktop.browse(uri);
					}
				} catch (Exception e2) {
					// TODO: handle exception
					//BurpExtender.this.callbacks.printError(e2.getMessage());
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
					//sortedColumn = table.getRowSorter().getSortKeys().get(0).getColumn();
					combinationConfig.setSortedColumn(table.getRowSorter().getSortKeys().get(0).getColumn());
					//System.out.println(sortedColumn);
					//sortedMethod = table.getRowSorter().getSortKeys().get(0).getSortOrder();
					combinationConfig.setSortedMethod(table.getRowSorter().getSortKeys().get(0).getSortOrder());
					//System.out.println(sortedMethod); //ASCENDING   DESCENDING
				} catch (Exception e1) {
					//sortedColumn = -1;
					combinationConfig.setSortedColumn(-1);
					//sortedMethod = null;
					combinationConfig.setSortedMethod(null);
					//BurpExtender.this.callbacks.printError(e1.getMessage());
				}
//				System.out.println(sortedColumn);
//				System.out.println(sortedMethod);
				//lblOrderMethod.setText(table.getColumnName(sortedColumn)+" "+sortedMethod);
				lblOrderMethod.setText(table.getColumnName(combinationConfig.getSortedColumn())+" "+combinationConfig.getSortedMethod());
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
					String str = combineString(getParaFromTable(),combinationConfig);
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
		buttonGroupKeyConfiguration.add(chckbxSameAsPara);

		chckbxAppendToEnd = new JCheckBox("Append to the end of sorted Parameters. eg. &key=secretkey");
		panel_8.add(chckbxAppendToEnd);
		buttonGroupKeyConfiguration.add(chckbxAppendToEnd);

		JLabel lblNewLabel_1 = new JLabel("[3] How To Combine :");//new JLabel("[3] How To Combine\uFF1A ");
		panel_8.add(lblNewLabel_1);

		chckbxKeySymbolValue = new JCheckBox("Use KeySymbolValue");
		panel_8.add(chckbxKeySymbolValue);
		chckbxKeySymbolValue.setSelected(true);
		buttonGroupCombinationType.add(chckbxKeySymbolValue);

		chckbxOnlyUseValue = new JCheckBox("Only Use Value");
		panel_8.add(chckbxOnlyUseValue);
		buttonGroupCombinationType.add(chckbxOnlyUseValue);

		chckbxOnlyUseKeyValue = new JCheckBox("Only Use KeyValue");
		panel_8.add(chckbxOnlyUseKeyValue);
		buttonGroupCombinationType.add(chckbxOnlyUseKeyValue);

		chckbx10timestamp = new JCheckBox("10-digtal-timestamp");
		panel_8.add(chckbx10timestamp);
		buttonGroupTimestamp.add(chckbx10timestamp);

		chckbx13timestamp = new JCheckBox("13-digtal-timestamp");
		chckbx13timestamp.setSelected(true);
		panel_8.add(chckbx13timestamp);
		buttonGroupTimestamp.add(chckbx13timestamp);


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
		buttonGroupSignAlgorithm.add(chckbxMD5);

		chckbxMD5u = new JCheckBox("MD5[upper]");
		chckbxMD5u.setSelected(false);
		GridBagConstraints gbc_chckbxMD5u = new GridBagConstraints();
		gbc_chckbxMD5u.anchor = GridBagConstraints.NORTHWEST;
		gbc_chckbxMD5u.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxMD5u.gridx = 0;
		gbc_chckbxMD5u.gridy = 2;
		panel_10.add(chckbxMD5u, gbc_chckbxMD5u);
		buttonGroupSignAlgorithm.add(chckbxMD5u);

		chckbxSHA1 = new JCheckBox("SHA1");
		chckbxSHA1.setSelected(false);
		GridBagConstraints gbc_chckbxSHA1 = new GridBagConstraints();
		gbc_chckbxSHA1.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxSHA1.gridx = 1;
		gbc_chckbxSHA1.gridy = 1;
		panel_10.add(chckbxSHA1, gbc_chckbxSHA1);
		buttonGroupSignAlgorithm.add(chckbxSHA1);

		chckbxSHA256 = new JCheckBox("SHA256");
		chckbxSHA256.setSelected(false);
		GridBagConstraints gbc_chckbxSHA256 = new GridBagConstraints();
		gbc_chckbxSHA256.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxSHA256.gridx = 1;
		gbc_chckbxSHA256.gridy = 2;
		panel_10.add(chckbxSHA256, gbc_chckbxSHA256);
		buttonGroupSignAlgorithm.add(chckbxSHA256);


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
		}else if (chckbxSHA256.isSelected()) {
			return "SHA256";
		}else {
			return "null";
		}
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
		} else if ("SHA256".equals(getSignAlgorithm())) {
			sign = CSHA256.SHA256(str);
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

	public String getHostFromUI(){
		String domain = "";
		domain = textFieldDomain.getText();
		return domain ;
	}
	//各种从图形面板或者从数据包获取参数，获取配置的函数。--end

	// Function to combine strings from a map
	public String combineString(Map<String, String> paraMap,CCombinationConfig combinationConfig){//, boolean onlyKeyValue, boolean onlyValue, String paraConnector, String paraPrefixer, String paraSuffixer) {
		// Get the secret key
		if (textFieldSecretKey.getText() != null && !textFieldSecretKey.getText().isEmpty()){
			combinationConfig.setSecretKey(textFieldSecretKey.getText());
		}else {
			combinationConfig.setSecretKey(null);
		}
		// Get the secret key configuration
		if(chckbxAppendToEnd.isSelected()){
			combinationConfig.setKeyConfiguration(ICombinationConfig.KeyConfiguration.APPEND_TO_END);//"APPEND_TO_END";
		} else if (chckbxSameAsPara.isSelected()) {
			combinationConfig.setKeyConfiguration(ICombinationConfig.KeyConfiguration.SAME_AS_PARA);
		}
		// Get the combine configuration
		if(chckbxOnlyUseKeyValue.isSelected()){
			combinationConfig.setCombinationType(ICombinationConfig.CombinationType.ONLY_KEY_VALUE);
		}else if(chckbxOnlyUseValue.isSelected()) {
			combinationConfig.setCombinationType(ICombinationConfig.CombinationType.ONLY_VALUE);
		}else if(!chckbxOnlyUseKeyValue.isSelected() && !chckbxOnlyUseValue.isSelected()){
			combinationConfig.setCombinationType(ICombinationConfig.CombinationType.KEY_SYMBOL_VALUE);
		}
		// Get the parameter connector
		combinationConfig.setParaConnector(textFieldParaConnector.getText());

		// Get the Prefixer
		if(textFieldParaPrefixer.getText()!=null && !textFieldParaPrefixer.getText().isEmpty()){
			combinationConfig.setParaPrefixer(textFieldParaPrefixer.getText());
		}else {
			combinationConfig.setParaPrefixer(null);
		}
		// Get the Suffixer
		if(textFieldParaSuffixer.getText()!=null && !textFieldParaSuffixer.getText().isEmpty()){
			combinationConfig.setParaSuffixer(textFieldParaSuffixer.getText());
		}else {
			combinationConfig.setParaSuffixer(null);
		}

		// Create a string builder
		StringBuilder sb = new StringBuilder();
		// If the key is the same as the parameter
		if (ICombinationConfig.KeyConfiguration.SAME_AS_PARA.equals(combinationConfig.getKeyConfiguration())){
			// Get the text from the secret key
			combinationConfig.setSecretKey(textFieldSecretKey.getText());
			// If the secret key contains an equal sign and has two parts
			if(combinationConfig.getSecretKey().contains("=") & combinationConfig.getSecretKey().split("=").length==2){
				// Put the key and value into the map
				paraMap.put(combinationConfig.getSecretKey().split("=")[0], combinationConfig.getSecretKey().split("=")[1]);
			}
		}
		// If the order method is custom
		if ("Custom Order".equals(lblOrderMethod.getText())) {
			Map<String, String> sortedMap;

			combinationConfig.setSortedMethod(UNSORTED);
			sortedMap = CMapSort.sortMapByKey(paraMap, combinationConfig.getSortedMethod().toString());
			sb.append(CMapSort.combineMapEntry(sortedMap, combinationConfig));//combinationConfig.getKeyConfiguration(), combinationConfig.getParaConnector(), combinationConfig.getParaPrefixer(), combinationConfig.getParaSuffixer()));
			// Otherwise
		} else {
			// Create a sorted map
			Map<String, String> sortedMap;
			// If the sorted column is 0
			if(combinationConfig.getSortedColumn() == 0) {
				// Sort the map by key
				combinationConfig.setSortedMethod(UNSORTED);
				sortedMap = CMapSort.sortMapByKey(paraMap, combinationConfig.getSortedMethod().toString());
				// Otherwise
			} else {
				// Sort the map by value

				combinationConfig.setSortedMethod(UNSORTED);
				sortedMap = CMapSort.sortMapByValue(paraMap, combinationConfig.getSortedMethod().toString());
			}
			// Append the combined map entry
			sb.append(CMapSort.combineMapEntry(sortedMap, combinationConfig));//onlyKeyValue, onlyValue, paraConnector, paraPrefixer, paraSuffixer));
		}
		// If the key should be appended to the end
		if (ICombinationConfig.KeyConfiguration.APPEND_TO_END.equals(combinationConfig.getKeyConfiguration())) {
			// Get the text from the secret key
			combinationConfig.setSecretKey(textFieldSecretKey.getText());
			// Append the secret key
			sb.append(combinationConfig.getSecretKey());
		}
		// Return the string
		return sb.toString();
	}


}
