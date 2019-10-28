import * as url from 'url';
import Zipper from './zipper';
import * as request from 'superagent';

/**
 * Implements low-level API request logic.
 */
export class HttpClient {
    private static readonly JSON_V1 = 'application/json;v=1.0';

    private readonly baseUrl: string;

    private readonly zipper: Zipper;
    accessToken: string = '';

    constructor(baseUrl: string, accessToken?: string) {
        this.baseUrl = baseUrl;

        if (accessToken) {
            this.accessToken = accessToken;
        }

        this.zipper = new Zipper();
    }

    async login(username: string, password: string) {
        const fullUrl = this.getFullUrl('auth/identity/connect/token');
        return await request
            .post(fullUrl)
            .type('form')
            .send({
                userName: username,
                password: password,
                grant_type: 'password',
                scope: 'sast_rest_api offline_access',
                client_id: 'resource_owner_client',
                client_secret: '014DF517-39D1-4453-B7B3-9930C563627C'
            })
            .then(
                (response: request.Response) => {
                    console.log('Login was successful');
                    this.accessToken = response.body.access_token;
                },
                (err: any) => {
                    console.log('Login failed');
                    throw err;
                }
            );
    }

    getRequest(relativePath: string): Promise<any> {
        return this.sendSimpleRequest(relativePath);
    }

    postRequest(relativePath: string, data: object): Promise<any> {
        return this.sendSimpleRequest(relativePath, data);
    }

    private sendSimpleRequest(relativePath: string, data?: object): Promise<any> {
        const method = data ? 'post' : 'get';
        const fullUrl = this.getFullUrl(relativePath);

        let result = request[method](fullUrl)
            .auth(this.accessToken, {type: 'bearer'})
            .set('Content-Type', HttpClient.JSON_V1);

        if (data) {
            result = result.send(data);
        }

        return result.then((response: request.Response) => response.body,
            (err: any) => {
                console.log(`${method.toUpperCase()} request failed to ${fullUrl}`);
                throw err;
            });
    }

    postMultipartRequest(relativePath: string,
                         fields: { [fieldName: string]: any },
                         attachments: { [fieldName: string]: string }) {
        const fullUrl = this.getFullUrl(relativePath);

        let result = request
            .post(fullUrl)
            .auth(this.accessToken, {type: 'bearer'})
            .accept('application/json')
            .field(fields);

        for (const prop in attachments) {
            result = result.attach(prop, attachments[prop]);
        }

        return result.then(
            (response: request.Response) => {
                return response.body;
            },
            (err: any) => {
                console.log(`Multipart request failed to ${fullUrl}`);
                throw err;
            }
        );
    }

    private getFullUrl(relativePath: string) {
        return url.resolve(this.baseUrl, relativePath);
    }
}
