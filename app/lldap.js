var settings = require('../config/config.json');
var ldap = require('ldapjs');
var assert = require('assert')


function Lldap(){
    this.client = ldap.createClient({ url: settings.ldap.url});
    this.client.bind(settings.ldap.bindDn, settings.ldap.bindCredentials, function(err) {
	assert.ifError(err);
    });	
}

//Find the max Uid in ldap
Lldap.prototype.getMaxUid=function(success, error){
    console.time('maxuid search time');
    var opts = {filter: 'objectClass=posixAccount', scope: 'sub', attributes: 'uidNumber' };
    var maxUid=0, curUid=0;
    this.client.search(settings.ldap.searchBase, opts, function(err, res) {
	assert.ifError(err);
	res.on('searchEntry', function(entry) {
	    curUid=parseInt(entry.object.uidNumber);
	    if(maxUid < curUid)  maxUid=curUid
	    //console.log('entry: ' + JSON.stringify(entry.object));
	});
	res.on('error', function(err) {
	    error(err)
	});
	res.on('end', function(result) {
	    console.timeEnd('maxuid search time');
	    success(maxUid);
	});
    });
};

//Check if an entry is already on ldap
Lldap.prototype.validate=function(newEntry, response, success, error){
    console.time('search time');
    var errorMsg;
    var add = false;
    var opts =	{ filter: '(|(cn='+newEntry.cn+')(mail='+newEntry.mail+')(uid='+newEntry.uid+'))', scope: 'sub', attributes: ['cn', 'mail', 'uid'] };
    this.client.search(settings.ldap.searchBase, opts, function(err, res) {
	assert.ifError(err);
	res.on('searchEntry', function(entry) {
	    if(entry.object.mail == newEntry.mail && entry.object.uid == newEntry.uid && entry.object.cn == newEntry.cn) errorMsg ="Can't create this account, is already in use.";
	    else if(entry.object.mail == newEntry.mail && entry.object.uid == newEntry.uid) errorMsg ='This email and user name are already in use.';
	    else if(entry.object.mail == newEntry.mail )errorMsg='The email is already in use, try another.';
	    else if(entry.object.uid == newEntry.uid)errorMsg='The username is already in use, try another.';
	    else if(entry.object.cn == newEntry.cn) errorMsg='We found an account with that name.';
	    else console.log('New entry is valid:' + newEntry);
	});
	res.on('error', function(err) {
	    console.log(err)
	    errorMsg='Failed to validate newEntry, must return a 500';
	});
	res.on('end', function(result) {
	    (errorMsg == undefined) ? success() : error(errorMsg, newEntry);
	});
    });    
}

//Add a new entry to ldap
Lldap.prototype.add=function(entry, res){
    var _self = this;
    var dn= 'cn='+entry.cn+','+settings.ldap.searchBase;
    _self.validate(entry, res, //first we need to check if it is not already in the directory,
		   function(){
		       _self.getMaxUid( //then we found out what uidNumber we should use
			   function(maxUid){
			       entry['uidNumber'] = ++maxUid;
			       entry['gidNumber'] = 501;
			       entry['loginShell']= '/bin/bash';
			       entry['homeDirectory']= '/home/users/'+ entry.uid;
			       entry['objectclass'] = ['inetOrgPerson','posixAccount','top'];
			       _self.client.add(dn, entry, function(err){ //and finally we run the add operation on ldap
				   if (err){
       				       console.log('ldap add failed:'+ JSON.stringify(entry));
				       res.status(500).send({'error':err.name})
				   }
				   else{
				       console.log('ldap add succesful:'+ JSON.stringify(entry));
				       entry['userPassword'] = '******';
				       res.status(201).send(entry);
				   }
			       });
			   },
			   function(err){
			       console.error('Error' + err);
			   });
		       
		   },
		   function(error, entry){
		       console.log('Error:'+ error + ' Entry:'+ JSON.stringify(entry));
		       res.status(400).send({'error':error})		 
		   });
}
module.exports = Lldap;
