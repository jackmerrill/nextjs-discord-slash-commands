/* eslint-disable default-case */
import { NextApiRequest, NextApiResponse } from 'next';
import nacl from 'tweetnacl';

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
        premium_since: Date?,
        permissions: string,
        pending: boolean,
        nick: string?,
        mute: boolean,
        joined_at: Date,
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

export default (req: NextApiRequest, res: NextApiResponse) => {
  const { PUBLIC_KEY } = process.env;

  const signature = req.headers['X-Signature-Ed25519'];
  const timestamp = req.headers['X-Signature-Timestamp'];
  const { body } = req;

  const isVerified = nacl.sign.detached.verify(
    Buffer.from(timestamp + body),
    Buffer.from(signature as string, 'hex'),
    Buffer.from(PUBLIC_KEY as string, 'hex'),
  );

  if (!isVerified) {
    return res.status(401).end('invalid request signature');
  }

  if (req.body.type === 1) {
    res.json({
      type: 1,
    });
  } else {
    const command = body as SlashCommandResponse;

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
};
