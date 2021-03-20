/* @TODO replace with your variables
 * ensure all variables on this page match your project
 */

export const environment = {
  production: false,
  apiServerUrl: 'http://127.0.0.1:5000', // the running FLASK api server url
  auth0: {
    url: 'dev-f8a4q20m.us', // the auth0 domain prefix
    audience: 'fsnd-project03-coffee', // the audience set for the auth0 app
    clientId: 'MzltMB80eOOhOBOQswf917pVrRey74d3', // the client id generated for the auth0 app
    callbackURL: 'http://localhost:8100', // the base url of the running ionic application. 
  }
};
