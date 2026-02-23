const VIDEOS = [
  {
    id: "PQDfvDpT5Ls",
    title: "Ad blocker exfiltrating every URL you visit",
    desc: "A popular ad blocker silently uploading your full browsing history to remote servers - every page, every click.",
  },
  {
    id: "UYwUmaVohQk",
    title: "WhatRuns caught scraping AI chats",
    desc: "WhatRuns was found harvesting full browsing URLs and the contents of AI chat sessions without any user knowledge or consent.",
  },
  {
    id: "IOdGJEky1SU",
    title: "StayFocusd: productivity tool or spyware?",
    desc: "A widely-trusted productivity extension demonstrated exfiltrating complete browsing history data in real time.",
  },
] as const;

export function VideosSection() {
  return (
    <section className="mx-auto max-w-6xl px-6 pt-8 pb-4">
      <h2 className="text-foreground mb-2 text-xl font-semibold">
        Caught in the wild
      </h2>
      <p className="text-muted-foreground mb-8 text-sm">
        Real extensions, real exfiltration - recorded and verified by our team.
      </p>
      <div className="grid gap-8 sm:grid-cols-3">
        {VIDEOS.map((video) => (
          <div key={video.id} className="flex flex-col gap-3">
            <div className="border-border overflow-hidden rounded-lg border">
              <iframe
                src={`https://www.youtube-nocookie.com/embed/${video.id}`}
                title={video.title}
                allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                allowFullScreen
                className="aspect-video w-full"
              />
            </div>
            <h3 className="text-foreground text-sm font-semibold">
              {video.title}
            </h3>
            <p className="text-muted-foreground text-xs leading-relaxed">
              {video.desc}
            </p>
          </div>
        ))}
      </div>
    </section>
  );
}
