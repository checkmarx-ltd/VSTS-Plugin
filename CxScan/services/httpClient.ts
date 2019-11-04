import * as url from 'url';
import * as request from 'superagent';
import {Logger} from "./logger";

interface RequestOptions {
    baseUrlOverride?: string;
    singlePostData?: object,
    multipartPostData?: {
        fields: { [fieldName: string]: any },

        // Key: attachment field name.
        // Value: paths of the file to attach.
        attachments: { [fieldName: string]: string }
    }
}

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
        const fullUrl = url.resolve(this.baseUrl, 'auth/identity/connect/token');
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
                    this.accessToken = response.body.access_token;
                },
                (err: any) => {
                    this.log.info('Login failed');
                    throw err;
                }
            );
    }

    getRequest(relativePath: string, baseUrlOverride?: string): Promise<any> {
        return this.sendRequest(relativePath, {baseUrlOverride});
    }

    postRequest(relativePath: string, data: object): Promise<any> {
        return this.sendRequest(relativePath, {singlePostData: data});
    }

    postMultipartRequest(relativePath: string,
                         fields: { [fieldName: string]: any },
                         attachments: { [fieldName: string]: string }) {
        return this.sendRequest(relativePath, {
            multipartPostData: {
                fields,
                attachments
            }
        });
    }

    private sendRequest(relativePath: string, options: RequestOptions) {
        const effectiveBaseUrl = options.baseUrlOverride || this.baseUrl;
        const fullUrl = url.resolve(effectiveBaseUrl, relativePath);

        const method = options.singlePostData || options.multipartPostData ? 'post' : 'get';

        let result = request[method](fullUrl)
            .auth(this.accessToken, {type: 'bearer'})
            .accept('json');

        if (options.singlePostData) {
            result = result.send(options.singlePostData);
        } else if (options.multipartPostData) {
            const {fields, attachments} = options.multipartPostData;
            result = result.field(fields);
            for (const prop in attachments) {
                result = result.attach(prop, attachments[prop]);
            }
        }

        return result.then(
            (response: request.Response) => {
                return response.body;
            },
            (err: any) => {
                this.log.info(`${method.toUpperCase()} request failed to ${fullUrl}`);
                throw err;
            }
        );
    }
}
