import * as url from 'url';
import * as request from 'superagent';
import {Logger} from "./logger";

/**
 * Implements low-level API request logic.
 */
export class HttpClient {
    private readonly baseUrl: string;

    accessToken: string = '';

    constructor(baseUrl: string, private readonly log: Logger, accessToken?: string) {
        this.baseUrl = baseUrl;

        if (accessToken) {
            this.accessToken = accessToken;
        }
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
                    this.log.info('Login was successful');
                    this.accessToken = response.body.access_token;
                },
                (err: any) => {
                    this.log.info('Login failed');
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
            .accept('json');

        if (data) {
            result = result.send(data);
        }

        return result.then((response: request.Response) => response.body,
            (err: any) => {
                this.log.info(`${method.toUpperCase()} request failed to ${fullUrl}`);
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
            .accept('json')
            .field(fields);

        for (const prop in attachments) {
            result = result.attach(prop, attachments[prop]);
        }

        return result.then(
            (response: request.Response) => {
                return response.body;
            },
            (err: any) => {
                this.log.info(`Multipart request failed to ${fullUrl}`);
                throw err;
            }
        );
    }

    private getFullUrl(relativePath: string) {
        return url.resolve(this.baseUrl, relativePath);
    }
}
