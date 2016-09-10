package ldap;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import com.sun.xml.internal.stream.Entity;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

/**
 * Ldap���������������ѯ����ɾ��
 * �ο�http://bbs.csdn.net/topics/390493306
 * @author M084806
 *
 */
public class LdapHelper {




	/**
	 * ��ȡldap����������
	 * @return
	 */
	@SuppressWarnings(value = "unchecked")
	public  DirContext getCtx() {
		DirContext ctx = null;
		//����Ѿ������ӵ�ֱ�ӷ���
//		if(null != ctx){
//			return ctx;
//		}
		//���Ӳ��Է�������������д��������ʽ��
		String ldapIP = "10.10.150.252";
		String ldapPort = "389";
		String account = "cn=syncuser,cn=config"; //binddn
		String password = "PWD4sync"; //bindpwd
		String root = "dc=sae,dc=com,dc=hk"; // root    ou=people,dc=sae,dc=com,dc=hk
		
		
				
		Hashtable env = new Hashtable();
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, "ldap://"+ldapIP+":"+ldapPort+"/" + root);
		env.put(Context.SECURITY_AUTHENTICATION, "simple");
		env.put(Context.SECURITY_PRINCIPAL, account );
		env.put(Context.SECURITY_CREDENTIALS, password);
		try {
		// ����ldap
			ctx = new InitialDirContext(env);
			System.out.println("��֤�ɹ�");
		} catch (javax.naming.AuthenticationException e) {
			e.printStackTrace();
			System.out.println("��֤ʧ��");
		} catch (Exception e) {
			System.out.println("��֤����");
		e.printStackTrace();
		}
		return ctx;
	}

	/**
	 * �ر�ldap������
	 */
	public  void closeCtx(DirContext dirCtx){
		try {
			if(dirCtx!=null){
				dirCtx.close();
				dirCtx = null;
			}
			
		} catch (NamingException ex) {
			Logger.getLogger(LdapHelper.class.getName()).log(Level.SEVERE, null, ex);
			ex.printStackTrace();
		}
	}
	
	/**
	 * �Ա�ldap������������ʹ������������Ƿ�һ��
	 * @param ldappw
	 * @param inputpw
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	@SuppressWarnings(value = "unchecked")
	public  boolean verifySHA(String ldappw, String inputpw)	throws NoSuchAlgorithmException {
	
		//MessageDigest �ṩ����ϢժҪ�㷨���� MD5 �� SHA���Ĺ��ܣ�����LDAPʹ�õ���SHA-1
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		
		//ȡ�������ַ�
		if (ldappw.startsWith("{SSHA}")) {
			ldappw = ldappw.substring(6);
		} else if (ldappw.startsWith("{SHA}")) {
			ldappw = ldappw.substring(5);
		}
		
		//����BASE64
		byte[] ldappwbyte = Base64.decode(ldappw);
		byte[] shacode;
		byte[] salt;
		
		//ǰ20λ��SHA-1���ܶΣ�20λ�����������ʱ���������
		if (ldappwbyte.length <= 20) {
			shacode = ldappwbyte;
			salt = new byte[0];
		} else {
			shacode = new byte[20];
			salt = new byte[ldappwbyte.length - 20];
			System.arraycopy(ldappwbyte, 0, shacode, 0, 20);
			System.arraycopy(ldappwbyte, 20, salt, 0, salt.length);
		}
		
		//���û������������ӵ�ժҪ������Ϣ
		md.update(inputpw.getBytes());
		// �����������ӵ�ժҪ������Ϣ
		md.update(salt);
		
		//��SSHA�ѵ�ǰ�û�������м���
		byte[] inputpwbyte = md.digest();
		
		//����У����
		return MessageDigest.isEqual(shacode, inputpwbyte);
	}
	
	
	/**
	 * ��֤�˻���¼������ȷ���
	 * @param usr
	 * @param pwd
	 * @return
	 */
//�Ѿ��ع�
//	public  boolean authenticate(String uid, String pwd) {
//		 boolean success = false;
//		 DirContext ctx = null;
//		 try {
//			 ctx = this.getCtx();
//			 SearchControls constraints = new SearchControls();
//			 constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
////			  constraints.setSearchScope(SearchControls.ONELEVEL_SCOPE);
//			// ��ѯָ���û�
//			 NamingEnumeration en = ctx.search("", "uid=" + uid, constraints); 
//			//����з������������ѭ������ȡ�û����룬�ٱ�����ܺ�Ա��Ƿ�һ��
//			 while (en != null && en.hasMoreElements()) {
//				 Object obj = en.nextElement();
//				 if (obj instanceof SearchResult) {
//					 SearchResult si = (SearchResult) obj;
//					 //��ȡname����
//					 System.out.println("name: " + si.getName());
//					 Attributes attrs = si.getAttributes();
//					 if (attrs == null) {
//						 System.out.println("No attributes");
//					 } else {
//						 //��ȡ�������ϵ�����
//						 Attribute attr = attrs.get("userPassword");
//						 Object o = attr.get();
//						 byte[] s = (byte[]) o;
//						 String pwd2 = new String(s);
//						 //��֤�����Ƿ���ȷ
//						 success = this.verifySHA(pwd2, pwd);
//						 return success;
//					 }
//				 } else {
//					 System.out.println(obj);
//				 }
//				 System.out.println("===================");
//			 }
//			 //�ر�����
//			 	this.closeCtx(ctx);
//		 } catch (NoSuchAlgorithmException ex) {
//			this.closeCtx(ctx);
//			 Logger.getLogger(LdapHelper.class.getName()).log(Level.SEVERE, null, ex);
//		 } catch (NamingException ex) {
//			 this.closeCtx(ctx);
//			 	Logger.getLogger(LdapHelper.class.getName()).log(Level.SEVERE, null, ex);
//			 }
//		 	return false;
//		 }
	
	/**
	 * ��֤�˻���¼������ȷ���
	 * @param usr
	 * @param pwd
	 * @return
	 */
	public  boolean authenticate(String uid, String pwd) {
		boolean success = false;
		//��ȡladp�û������� 
		Map<String,String> map = this.getUser(uid);

		String pwd2 = map.get("userPassword");
		if(null == pwd2){
			return success;
		}
		
		
		 //��֤�����Ƿ���ȷ
		try {
			success = this.verifySHA(pwd2, pwd);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return success;
	}
	
	
	
	/**
	 * ֱ��ʹ��uid��������
	 * @param uid
	 * @param pwd
	 * @return
	 */
//  Ȩ�޲��㣬�޷�����ע�͵�
	public boolean updatePwdLdapImmediately(String uid,String attr, String value) {
		 boolean success = false;
		 DirContext ctx = null;
		 try {
			 ctx = this.getCtx();
			 ModificationItem[] modificationItem = new ModificationItem[1];
			 modificationItem[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(attr, value));
			 ctx.modifyAttributes("uid=" + uid, modificationItem);
			 this.closeCtx(ctx);
			 return true;
		 } catch (NamingException ex) {
			 this.closeCtx(ctx);
			 Logger.getLogger(LdapHelper.class.getName()).log(Level.SEVERE, null, ex);
		 }
		 return success;
	}
	
	

	
	
	
	/**
	 * ��ѯ�Ƿ��иÿͻ���Ȼ���������         
	 * @param uid
	 * @param pwd
	 * @return
	 */
//  Ȩ�޲��㣬ע�͵�
	public boolean updatePwdLdapWithCheck(String uid, String pwd) {
		//��ȡladp�û������� 
		Map<String,String> map = this.getUser(uid);
		 if(null == map){
			 return false;
		 }
		 String getUid = map.get("uid");
		 boolean isSuccess =  updatePwdLdapImmediately(getUid,"userPassword",pwd);
		 return isSuccess;
	}
	
	
	
	/**
	 * ͨ��uid��ȡ�ͻ�
	 * @param usr
	 * @param pwd
	 * @return
	 */
	public  Map<String,String> getUser(String uid) {
		 DirContext ctx = null;
		 Map<String,String> beanMap = new HashMap<String,String>();
		 try {
			 ctx = this.getCtx();
			 SearchControls constraints = new SearchControls();
			 constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
//			  constraints.setSearchScope(SearchControls.ONELEVEL_SCOPE);
			// ��ѯָ���û�
			 NamingEnumeration<SearchResult> en = ctx.search("", "uid=" + uid, constraints); 
		     // ����鵽������  
		     while (null != en && en.hasMore()) {  
		            SearchResult result = en.next();  
		            NamingEnumeration<? extends Attribute> attrs = result.getAttributes().getAll();  
		            
		            //��ȡ��������
		            while (attrs.hasMore()) {  
		                Attribute attr = attrs.next();  
		                if(attr.get() == null){
		                	 beanMap.put(attr.getID(),"");
		                }else{
		                	Object o = attr.get();
		                	 if (o instanceof String) {
		                		beanMap.put(attr.getID(),attr.get().toString());
		                	 }else{
		                		byte[] s = (byte[]) o;
								String userAtt = new String(s);
								beanMap.put(attr.getID(),userAtt);
		                	 }
		                }
		            }  
		     }  
		    	                 for (String str : beanMap.keySet()) {  
		    	                     System.out.println(str+" : "+beanMap.get(str));
		    	                     
		    	                 }  
		     					System.out.println("============"); 
			 
			 //�ر�����
		     this.closeCtx(ctx);
			 return beanMap;
			 
		 } catch (NamingException ex) {
			 	this.closeCtx(ctx);
			 	Logger.getLogger(LdapHelper.class.getName()).log(Level.SEVERE, null, ex);
			 }
		 	return beanMap;
		 }
	
	
	
	
	/**
	 * �����û�
	 * @param usr
	 * @param pwd
	 * @return
	 */

	public  boolean addUser(Map<String,String> beanMap) {
		if(null == beanMap){
			return false;
		}
		
		boolean success = false;
		 DirContext ctx = null;
		 try {
			 ctx = this.getCtx();
			 BasicAttributes attrsbu = new BasicAttributes();
			 BasicAttribute objclassSet = new BasicAttribute("objectclass");
			 objclassSet.add("person");
			 objclassSet.add("top");
			 objclassSet.add("organizationalPerson");
			 objclassSet.add("inetOrgPerson");
			 attrsbu.put(objclassSet);
			 //ѭ����beanMap�Ž�ȥ
			 for (String key : beanMap.keySet()) {  
				 attrsbu.put(key,beanMap.get(key));
             }  
			 ctx.createSubcontext("cn=" + beanMap.get("cn") + ",ou=People", attrsbu);
			 this.closeCtx(ctx);
			 return true;
		 } catch (NamingException ex) {
			 this.closeCtx(ctx);
			 Logger.getLogger(LdapHelper.class.getName()).log(Level.SEVERE, null, ex);
		 }
		 	return false;
		 }
	
	
	/**
	 * ͨ��cnɾ���û��������ʹ��
	 * @param uid
	 * @return
	 */
	public boolean deleteUser(String uid,String cn){
		DirContext ctx = null;
		ctx = this.getCtx();
		try {
	        String userDN = "cn="+cn+",ou=People";
	        ctx.destroySubcontext(userDN);  
			this.closeCtx(ctx);
			return true;
		} catch (NamingException e) {
			 this.closeCtx(ctx);
			 Logger.getLogger(LdapHelper.class.getName()).log(Level.SEVERE, null, e);
		} 
		return false;
	}
	
	
	
	
	
	
	/**
	 * ��ѯ�������Ժͷ���Ӧ��
	 * �ο�http://www.jb51.net/article/41447.htm
	 * @throws Exception
	 */
    public void testSearch() throws Exception {  
    	DirContext ctx = this.getCtx();
        // ���ù�������  
        String uid = "m084753";  //��Ȩ
//    	 String uid = "m084750";	//��֦
//    	 String uid = "m084806";
//    	 String uid = "m111111";
    	 
        //����������ѯ
//        String filter = "(&(objectClass=top)(objectClass=organizationalPerson)(uid=" + uid + "))"; 
        String filter = "objectClass=*";
       
        // ����Ҫ��ѯ���ֶ�����  
        String[] attrPersonArray = { "uid", "userPassword", "displayName", 
        		"cn", "sn","email", "mail", "description","city","country","dept","location","ext","title","department","phone" };  
        SearchControls searchControls = new SearchControls();  
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);  
        

        // ���Ʒ��ص���Ϣ
        // ���ý������ص�Attribute  
        //searchControls.setReturningAttributes(attrPersonArray);  
        
        //��ѯ���е���Ϣ
        searchControls.setReturningAttributes(null);  
        
                
        // ���������ֱ�Ϊ��  
        // �����ģ�     Ϊ�ձ�ʾ����ȫ��
        // Ҫ���������ԣ�     ���ΪobjectClass=*���򷵻�Ŀ���������е����ж���  
        // ���������������ؼ������  searchControls.setReturningAttributes(null)����ʹ��Ĭ�ϵ������ؼ�  
        NamingEnumeration<SearchResult> answer = ctx.search("", filter.toString(), searchControls);
        int i=0;
        HashMap<String,Integer> set = new HashMap<String,Integer>();
        
        // ����鵽������  
        while (null != answer && answer.hasMore()) {  
            SearchResult result = answer.next();  
            NamingEnumeration<? extends Attribute> attrs = result.getAttributes().getAll();  
            //��ȡ��������
            while (attrs.hasMore()) {  
                Attribute attr = attrs.next();  
               // System.out.println(attr.getID() + "=" + attr.get());  
                if("uid".equals(attr.getID().toString())){
                	set.put( attr.get().toString(), set.get(attr.get())==null?1:set.get(attr.get())+1);
                }
            }  
            i++;
           // System.out.println("============"+i); 
        }  
        
        
        for (String str : set.keySet()) {  
            System.out.println(str+" : "+set.get(str));
            
        }  
        
        
    }  
	
	
    
    
	
	
	

	public static void main(String[] args) {
		LdapHelper ldapHelper = new LdapHelper();
//		ldapHelper.getCtx();
		try {
//			boolean issuccess= ldapHelper.authenticate("m084806","chenshubin");
//			System.out.println(issuccess);
//			Map<String,String> beanMap = ldapHelper.getUser("m111111");
//			beanMap = ldapHelper.getUser("m111112");
//			beanMap = ldapHelper.getUser("m111113");
//			beanMap = ldapHelper.getUser("m111114");
//			Map<String,String> beanMap = new HashMap<String,String>();
//			beanMap.put("uid", "m111113");
//			beanMap.put("cn", "chen shu bin 3");
//			beanMap.put("userPassword", "chenshubin3");
//			beanMap.put("sn", "chen shu bin 3");
//			
//			ldapHelper.addUser(beanMap);
//			ldapHelper.updatePwdLdapWithCheck("m084806", "chenshubin1");
//			ldapHelper.testSearch();
//			ldapHelper.authenticate("m111112","chen shu bin 3");
//			boolean isSuccess = ldapHelper.deleteUser("m111114","chen shu bin 4");
//			System.out.println(isSuccess);
//			
//			Map<String,String> beanMap = ldapHelper.getUser("m111113");
//			boolean issuccess= ldapHelper.authenticate("m111113","chenshubin3");
//			System.out.println(issuccess);
			ldapHelper.updatePwdLdapWithCheck("m111113", "chenshubin5");
//			Map<String,String> beanMap  = new HashMap();
//			System.out.println(null == beanMap);
			
			
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

}

