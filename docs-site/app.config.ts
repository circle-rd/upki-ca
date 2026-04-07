export default defineAppConfig({
  docus: {
    title: "uPKI CA",
    description:
      "Self-hosted Certificate Authority — private PKI with zero internet dependency.",
    image: "/cover.png",
    socials: {
      github: "circle-rd/upki-ca",
    },
    github: {
      dir: "docs-site/content",
      branch: "main",
      repo: "upki-ca",
      owner: "circle-rd",
      edit: true,
    },
    aside: {
      level: 0,
      collapsed: false,
      exclude: [],
    },
    main: {
      padded: true,
      fluid: false,
    },
    header: {
      logo: false,
      showLinkIcon: true,
      exclude: [],
      fluid: false,
    },
    footer: {
      iconLinks: [
        {
          href: "https://github.com/circle-rd/upki-ca",
          icon: "simple-icons:github",
        },
      ],
    },
  },
});
