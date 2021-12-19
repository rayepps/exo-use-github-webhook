import _ from 'radash'
import type { Props, ApiFunction } from '@exobase/core'
import { errors } from '@exobase/core'
import { verify } from '@octokit/webhooks-methods'


export async function withGithubWebhook(func: ApiFunction, secret: string, props: Props) {
  const signature = props.req.headers['x-hub-signature-256'] as string
  if (!signature) {
    throw errors.badRequest({
      details: 'Missing required github signature header',
      key: 'exo.with-github-webhook.nana'
    })
  }
  const validate = _.try(async () => {
    // See: https://github.com/octokit/webhooks-methods.js/#sign
    const eventPayloadString = JSON.stringify(props.req.body) + '\n'
    return await verify(secret, eventPayloadString, signature)
  })
  const [err, isValid] = await validate()
  if (err) {
    throw errors.unknown({
      details: 'Error encountered while trying to validate webhook signature',
      key: 'exo.with-github-webhook.marlin'
    })
  }
  if (!isValid) {
    throw errors.badRequest({
      details: 'Request body failed webhook signature validation',
      key: 'exo.with-github-webhook.statix'
    })
  }
  return await func({
    ...props,
    args: {
      ...props.args,
      event: props.req.body
    }
  })
}

/**
 * Validates the signature of the incoming webhook payload
 * given the provided secret.
 */
export const useGithubWebhook = <TServices = Record<string, any>> (secret: string) => {
  return (func: ApiFunction) => _.partial(withGithubWebhook, func, secret)
}
