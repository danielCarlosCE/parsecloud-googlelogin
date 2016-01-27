/**
 * special thanks to this code https://groups.google.com/forum/#!topic/parse-developers/UUvTreGYOrI
 */

/**
* Load needed modules.
*/
var _ = require('underscore');
var Buffer = require('buffer').Buffer;

var clientsIds = ['iOSClientId','androidClientId'];
var googleValidateEndpoint = 'https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=';
var googlePlusEndpoint = 'https://www.googleapis.com/plus/v1/people/me?access_token=';

/**
 * In the Data Browser, set the Class Permissions for this class to
 * disable public access for Get/Find/Create/Update/Delete operations.
 * Only the master key should be able to query or write to these classes.
 */
var TokenStorage = Parse.Object.extend("TokenStorage");

var restrictedAcl = new Parse.ACL();
restrictedAcl.setPublicReadAccess(false);
restrictedAcl.setPublicWriteAccess(false);

/**
* Validade accessToken, if valid, call upsertGoogleUser function
* accessToken param is required
*/
Parse.Cloud.define('accessGoogleUser', function(req, res) {
    var data = req.params;
    
    if (!(data && data.accessToken)) {
        res.error('Invalid request received. "accessToken" is required');
        return;
    }

    Parse.Cloud.useMasterKey();
    Parse.Promise.as().then(function() {
        return callTokenInfoEndPoint(data.accessToken);
    }).then(function(httpResponse) {
        console.log("tokeninfo endpoint: " + httpResponse.text);
       
        var tokenInfoData = JSON.parse(httpResponse.text);
        // "Once you get these claims, you still need to check that the aud claim contains one of your app's client IDs."
        // from https://developers.google.com/identity/sign-in/ios/backend-auth
        if ( tokenInfoData && ( _.contains(clientsIds,tokenInfoData.aud) )) {
            var userId = tokenInfoData.sub;
            return upsertGoogleUser(data.accessToken, userId);
        } else {
            return Parse.Promise.error("Unable to parse Google data");
        }

    }).then(function(user) {  
         // send back the session token in the response to be used with 'become/becomeInBackground' functions
        res.success(user.getSessionToken());

    }, function(error) {      
        if (error && error.code && error.error) {
            error = error.code + ' ' + error.error;
        }
        res.error(JSON.stringify(error));
    });

});

var callTokenInfoEndPoint = function(accessToken) {
    return Parse.Cloud.httpRequest({
        url: googleValidateEndpoint + accessToken
    });
};

/**
 * This function checks to see if this Google user has logged in before.
 * If the user is found, update the accessToken (if necessary) and return
 *   the user.  If not, register a new one.
 */
var upsertGoogleUser = function(accessToken, userId) {

    var query = new Parse.Query(TokenStorage);
    query.equalTo('accountId', userId);
    return query.first({
        useMasterKey: true
    }).then(function(tokenStorage) {

        if (!tokenStorage) {
            return newGoogleUser(accessToken);
        }

        var user = tokenStorage.get('user');
        return user.fetch({
            useMasterKey: true
        }).then(function(user) {

            if (accessToken !== tokenStorage.get('access_token')) {
                tokenStorage.set('access_token', accessToken);
            }

            // This save will not use an API request if the token was not changed.
            return tokenStorage.save(null, {
                useMasterKey: true
            });
        }).then(function(obj) {
            password = new Buffer(24);
            _.times(24, function(i) {
                password.set(i, _.random(0, 255));
            });
            password = password.toString('base64');
            user.setPassword(password);
            return user.save();
        }).then(function(user) {            
            return Parse.User.logIn(user.get('username'), password);
        }).then(function(user) {
            return Parse.Promise.as(user);
        });
    });
};

var newGoogleUser = function(accessToken) {
    var user = new Parse.User();

    return Parse.Cloud.httpRequest({
        url: googlePlusEndpoint + accessToken
    }).then(function(httpResponse) {
        //check the Logs in Data Browser to see the httpResponse 
        console.log("googleplus endpoint: " + httpResponse.text);
        var gPlusData = JSON.parse(httpResponse.text);
        if ( gPlusData ) {
            return gPlusData;
        } else {
            return Parse.Promise.error("Unable to parse Google data");
        }
    }).then(function(gPlusData){
        var username = new Buffer(24);
        var password = new Buffer(24);
        _.times(24, function(i) {
            username.set(i, _.random(0, 255));
            password.set(i, _.random(0, 255));
        });

        user.set("username", username.toString('base64'));
        user.set("password", password.toString('base64'));

        // "emails": [
        //   {
        //    "value": "abc@gmail.com",
        //    "type": "account"
        //   }
        // ]
        user.set("email", gPlusData.emails[0].value);

        // "name": {
        //   "familyName": "Abc",
        //   "givenName": "Def"
        // }
        var name = gPlusData.name.givenName + " " + gPlusData.name.familyName;
        user.set("name", name);

         // "image": {
         //  "url": "https://lh3.googleusercontent.com/ ... /photo.jpg?sz=50",
         //  "isDefault": false
         // },
        user.set('imageUrl', gPlusData.image.url);
        
        user.set('accountType', 'g');

        return user.signUp().then(function(user) {
            var tokenStorage = new TokenStorage();
            tokenStorage.set('user', user);
            tokenStorage.set('accountId', gPlusData.id);
            tokenStorage.set('access_token', accessToken);
            tokenStorage.setACL(restrictedAcl);
            return tokenStorage.save(null, {
                useMasterKey: true
            });
        }).then(function(tokenStorage) {
            return upsertGoogleUser(accessToken, gPlusData.id);
        });
    }, function(error) {     
        if (error && error.code && error.error) {
            error = error.code + ' ' + error.error;
        }
        res.error(JSON.stringify(error));
    });

};