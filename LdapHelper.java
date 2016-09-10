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
 * Ldap连接属性类包括查询，增删改
 * 参考http://bbs.csdn.net/topics/390493306
 * @author M084806
 *
 */
public class LdapHelper {




	/**
	 * 获取ldap服务器连接
	 * @return
	 */
	@SuppressWarnings(value = "unchecked")
	public  DirContext getCtx() {
		DirContext ctx = null;
		//如果已经有连接的直接返回
//		if(null != ctx){
//			return ctx;
//		}
		//连接测试服务器，这里请写成配置形式的
		String ldapIP = "aaaaa";
		String ldapPort = "389";
		String account = "cn=saa,cn=coaaag"; //binddn
		String password = "aaa"; //bindpwd
		String root = "dc=aa,dc=aa,dc=aa"; // root    ou=people,dc=sae,dc=com,dc=hk
		
		
				
		Hashtable env = new Hashtable();
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, "ldap://"+ldapIP+":"+ldapPort+"/" + root);
		env.put(Context.SECURITY_AUTHENTICATION, "simple");
		env.put(Context.SECURITY_PRINCIPAL, account );
		env.put(Context.SECURITY_CREDENTIALS, password);
		try {
		// 链接ldap
			ctx = new InitialDirContext(env);
			System.out.println("认证成功");
		} catch (javax.naming.AuthenticationException e) {
			e.printStackTrace();
			System.out.println("认证失败");
		} catch (Exception e) {
			System.out.println("认证出错：");
		e.printStackTrace();
		}
		return ctx;
	}

	/**
	 * 关闭ldap的连接
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
	 * 对比ldap服务器的密码和传进来的密码是否一致
	 * @param ldappw
	 * @param inputpw
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	@SuppressWarnings(value = "unchecked")
	public  boolean verifySHA(String ldappw, String inputpw)	throws NoSuchAlgorithmException {
	
		//MessageDigest 提供了消息摘要算法，如 MD5 或 SHA，的功能，这里LDAP使用的是SHA-1
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		
		//取出加密字符
		if (ldappw.startsWith("{SSHA}")) {
			ldappw = ldappw.substring(6);
		} else if (ldappw.startsWith("{SHA}")) {
			ldappw = ldappw.substring(5);
		}
		
		//解码BASE64
		byte[] ldappwbyte = Base64.decode(ldappw);
		byte[] shacode;
		byte[] salt;
		
		//前20位是SHA-1加密段，20位后是最初加密时的随机明文
		if (ldappwbyte.length <= 20) {
			shacode = ldappwbyte;
			salt = new byte[0];
		} else {
			shacode = new byte[20];
			salt = new byte[ldappwbyte.length - 20];
			System.arraycopy(ldappwbyte, 0, shacode, 0, 20);
			System.arraycopy(ldappwbyte, 20, salt, 0, salt.length);
		}
		
		//把用户输入的密码添加到摘要计算信息
		md.update(inputpw.getBytes());
		// 把随机明文添加到摘要计算信息
		md.update(salt);
		
		//按SSHA把当前用户密码进行计算
		byte[] inputpwbyte = md.digest();
		
		//返回校验结果
		return MessageDigest.isEqual(shacode, inputpwbyte);
	}
	
	
	/**
	 * 验证账户登录密码正确与否，
	 * @param usr
	 * @param pwd
	 * @return
	 */
//已经重构
//	public  boolean authenticate(String uid, String pwd) {
//		 boolean success = false;
//		 DirContext ctx = null;
//		 try {
//			 ctx = this.getCtx();
//			 SearchControls constraints = new SearchControls();
//			 constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
////			  constraints.setSearchScope(SearchControls.ONELEVEL_SCOPE);
//			// 查询指定用户
//			 NamingEnumeration en = ctx.search("", "uid=" + uid, constraints); 
//			//如果有返回数据则进入循环，获取用户密码，再编译加密后对比是否一样
//			 while (en != null && en.hasMoreElements()) {
//				 Object obj = en.nextElement();
//				 if (obj instanceof SearchResult) {
//					 SearchResult si = (SearchResult) obj;
//					 //获取name属性
//					 System.out.println("name: " + si.getName());
//					 Attributes attrs = si.getAttributes();
//					 if (attrs == null) {
//						 System.out.println("No attributes");
//					 } else {
//						 //获取服务器上的密码
//						 Attribute attr = attrs.get("userPassword");
//						 Object o = attr.get();
//						 byte[] s = (byte[]) o;
//						 String pwd2 = new String(s);
//						 //验证密码是否正确
//						 success = this.verifySHA(pwd2, pwd);
//						 return success;
//					 }
//				 } else {
//					 System.out.println(obj);
//				 }
//				 System.out.println("===================");
//			 }
//			 //关闭连接
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
	 * 验证账户登录密码正确与否，
	 * @param usr
	 * @param pwd
	 * @return
	 */
	public  boolean authenticate(String uid, String pwd) {
		boolean success = false;
		//获取ladp用户的数据 
		Map<String,String> map = this.getUser(uid);

		String pwd2 = map.get("userPassword");
		if(null == pwd2){
			return success;
		}
		
		
		 //验证密码是否正确
		try {
			success = this.verifySHA(pwd2, pwd);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return success;
	}
	
	
	
	/**
	 * 直接使用uid更新属性
	 * @param uid
	 * @param pwd
	 * @return
	 */
//  权限不足，无法测试注释掉
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
	 * 查询是否有该客户，然后更新密码         
	 * @param uid
	 * @param pwd
	 * @return
	 */
//  权限不足，注释掉
	public boolean updatePwdLdapWithCheck(String uid, String pwd) {
		//获取ladp用户的数据 
		Map<String,String> map = this.getUser(uid);
		 if(null == map){
			 return false;
		 }
		 String getUid = map.get("uid");
		 boolean isSuccess =  updatePwdLdapImmediately(getUid,"userPassword",pwd);
		 return isSuccess;
	}
	
	
	
	/**
	 * 通过uid获取客户
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
			// 查询指定用户
			 NamingEnumeration<SearchResult> en = ctx.search("", "uid=" + uid, constraints); 
		     // 输出查到的数据  
		     while (null != en && en.hasMore()) {  
		            SearchResult result = en.next();  
		            NamingEnumeration<? extends Attribute> attrs = result.getAttributes().getAll();  
		            
		            //获取对象属性
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
			 
			 //关闭连接
		     this.closeCtx(ctx);
			 return beanMap;
			 
		 } catch (NamingException ex) {
			 	this.closeCtx(ctx);
			 	Logger.getLogger(LdapHelper.class.getName()).log(Level.SEVERE, null, ex);
			 }
		 	return beanMap;
		 }
	
	
	
	
	/**
	 * 增加用户
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
			 //循环讲beanMap放进去
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
	 * 通过cn删除用户，请谨慎使用
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
	 * 查询所有属性和方法应用
	 * 参考http://www.jb51.net/article/41447.htm
	 * @throws Exception
	 */
    public void testSearch() throws Exception {  
    	DirContext ctx = this.getCtx();
        // 设置过滤条件  
        String uid = "m084753";  //子权
//    	 String uid = "m084750";	//发枝
//    	 String uid = "m084806";
//    	 String uid = "m111111";
    	 
        //设置条件查询
//        String filter = "(&(objectClass=top)(objectClass=organizationalPerson)(uid=" + uid + "))"; 
        String filter = "objectClass=*";
       
        // 限制要查询的字段内容  
        String[] attrPersonArray = { "uid", "userPassword", "displayName", 
        		"cn", "sn","email", "mail", "description","city","country","dept","location","ext","title","department","phone" };  
        SearchControls searchControls = new SearchControls();  
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);  
        

        // 定制返回的信息
        // 设置将被返回的Attribute  
        //searchControls.setReturningAttributes(attrPersonArray);  
        
        //查询所有的信息
        searchControls.setReturningAttributes(null);  
        
                
        // 三个参数分别为：  
        // 上下文；     为空表示搜索全部
        // 要搜索的属性，     如果为objectClass=*，则返回目标上下文中的所有对象；  
        // 控制搜索的搜索控件，如果  searchControls.setReturningAttributes(null)，则使用默认的搜索控件  
        NamingEnumeration<SearchResult> answer = ctx.search("", filter.toString(), searchControls);
        int i=0;
        HashMap<String,Integer> set = new HashMap<String,Integer>();
        
        // 输出查到的数据  
        while (null != answer && answer.hasMore()) {  
            SearchResult result = answer.next();  
            NamingEnumeration<? extends Attribute> attrs = result.getAttributes().getAll();  
            //获取对象属性
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
	
	
    
    
	
	
	

}

