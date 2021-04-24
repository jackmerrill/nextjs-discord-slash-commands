import NextAuth from 'next-auth';
import Providers from 'next-auth/providers';

export default NextAuth({
  providers: [
    Providers.Discord({
      clientId: process.env.DISCORD_ID,
      clientSecret: process.env.DISCORD_SECRET,
      scope: 'identify bot applications.commands',
    }),
  ],

  callbacks: {
    jwt(token) {
      // console.log(token, user, account, profile, newUser);
      return token;
    },
  },
});
