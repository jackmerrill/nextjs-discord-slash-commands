/* eslint-disable default-case */
import { NextApiRequest, NextApiResponse } from 'next';
import nacl from 'tweetnacl';
import getRawBody from 'raw-body';

interface SlashCommandResponse {
    type: number,
    token: string,
    member: {
        user: {
            id: string,
            username: string,
            avatar: string,
            discriminator: string,
            public_flags: string
        },
        roles: string[],
        premium_since: Date | null,
        permissions: string,
        pending: boolean,
        nick: string | null,
        mute: boolean,
        joined_at: Date | null,
        is_pending: boolean,
        deaf: boolean
    },
    id: string,
    guild_id: string,
    data: {
        options: {
          name: string,
          value: string
        }[],
        name: string,
        id: string
    },
    channel_id: string
}

export const config = {
  api: {
    bodyParser: false,
  },
}

export default async (req: NextApiRequest, res: NextApiResponse) => {
  if (!req.body) {
    let body;
    try {
      body = await getRawBody(req, {
        encoding: true
      })
    } catch (e) {
      console.error(e)
    }
    const signature = req.headers['x-signature-ed25519'];
    const timestamp = req.headers['x-signature-timestamp'];

    if (!signature) {
      return res.status(401).end('invalid request signature');
    }
    
    if (!timestamp || !body) {
      return res.status(401).end('no timestamp or body');
    }

    const isVerified = nacl.sign.detached.verify(
      Buffer.from(timestamp + body),
      Buffer.from(signature as string, 'hex'),
      Buffer.from(process.env.PUBLIC_KEY as string, 'hex'),
    );

    if (!isVerified) {
      return res.status(401).end('invalid request signature');
    }

    const parsedBody = JSON.parse(body)

    if (parsedBody.type === 1) {
      res.json({
        type: 1,
      });
    } else {
      const command = parsedBody as SlashCommandResponse;

      switch (command.data.name) {
        case 'ping': {
          res.json({
            type: 4,
            data: {
              content: 'Pong!',
            },
          });
        }
      }
    }
  }
};
